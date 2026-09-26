# The SBOM this tree produces meets the NTIA minimum elements, and the question
# could be asked at all (CLOUD-580, CLOUD-631, CLOUD-666; ported off
# `mise-tasks/ntia-check.sh` under CLOUD-1717).
#
# THE CLAUSE SET IS THE CHECKER'S, named by its own `--comply` flag
# (`ntia-conformance-checker`, CLOUD-279 verdict 1). This module owns no clause
# list: `[tasks.ntia-record]` derives the document through `[tasks.sbom]`
# into scratch — so the gate never writes the tree it judges, and judges the bytes
# a release would publish — runs the checker once per standard, and records its
# EXIT CODE. The spawn stays outside because house style §5 makes `check`
# incapable of one; what moved in here is the adjudication.
#
# THE VERDICT IS THE EXIT CODE, NEVER THE REPORT (CLOUD-93). The producer records
# the checker's report counts beside the code for a reader, and nothing below
# reads them: a checker that writes a conformant report and exits non-zero is
# nonconformant here.
#
# TWO CLASSES, AND THEY MUST NOT COLLAPSE. `manifest cover partial` is the
# document failing a standard. `manifest check unread` is the question being
# unaskable: no `spdxVersion`, one this gate cannot classify, or a standard that
# requires an SPDX 3 document over a document that is not one (CLOUD-666 —
# `fsct3-min` reads a field its checker only populates for `sbom_spec == "spdx3"`,
# and syft emits SPDX 2.3, so its refusal was a constant read for two months as a
# document nobody had enriched). The spec is read from the DOCUMENT, so if the
# producer ever emits SPDX 3 the standard becomes askable with no edit here.
#
# COULD-NOT-LOOK. Every exit-2 arm of the retired program that is about the
# MECHANISM — no executable producer, no checker, a checker not answering
# `--version`, no derivable or readable document — is the producer refusing at
# exit 3 and recording nothing. The arms that are about the DOCUMENT's spec are
# recorded and raised here, as a finding, never a pass. A record missing a
# reading is torn, and torn is `manifest check unread` too.
#
#MUTANT-SUITE crates/batten/tests/it/ntia.rs
#MUTANT nonconformant-sbom-passes|s@^\tentry.exit != "0"$@\tfalse@|a_nonconformant_document_fails
#MUTANT precondition-ignores-the-spec|s@^\tspec(version) != "spdx3"$@\tfalse@|an_spdx3_only_standard_over_an_spdx2_document_is_unread
#MUTANT precondition-guesses-an-absent-spec|s@^\tversion == ""$@\tfalse@|a_document_declaring_no_spdx_version_is_unread
#MUTANT torn-record-passes|s@^\tnot complete$@\tfalse@|a_record_missing_a_reading_is_torn

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ntia

import rego.v1

rules contains "manifest cover other"

lines := input.tree.records.ntia

# The standards that require an SPDX 3 document. Data, not a heuristic: each is
# one whose `check_compliance()` reads a field `get_sbom_types()` only populates
# for `sbom_spec == "spdx3"`.
spdx3_only := {"fsct3-min"}

rows(kind, width) := [columns |
	some line in lines
	columns := split(line, "\t")
	count(columns) == width
	columns[0] == kind
]

standards := [{"name": columns[1], "exit": columns[2]} | some columns in rows("standard", 4)]

single(kind) := value if {
	found := rows(kind, 2)
	count(found) == 1
	value := found[0][1]
}

document_name := single("document")

version := single("spdx-version")

complete if {
	document_name
	is_string(version)
	count(standards) > 0
}

spec(value) := "spdx3" if startswith(value, "SPDX-3")

spec(value) := "spdx2" if startswith(value, "SPDX-2")

pointer(token) := sprintf("%s#%s", [document_name, token])

# Present and torn: a reading is missing, so what is judged would be part of it.
violation contains {
	"rule": "manifest cover other",
	"verdict": "manifest check unread",
	"subjects": [{"path": "ntia#torn"}],
} if {
	lines
	not complete
}

# ABSENT IS NEVER A PASS: a document declaring no spec is one whose spec could not
# be looked at, and a precondition clearing what it cannot classify is the silent
# return CLOUD-666 closed.
violation contains {
	"rule": "manifest cover other",
	"verdict": "manifest check unread",
	"subjects": [{"path": pointer("spdx-version-absent")}],
} if {
	complete
	version == ""
}

violation contains {
	"rule": "manifest cover other",
	"verdict": "manifest check unread",
	"subjects": [{"path": pointer("spdx-version-unknown")}],
} if {
	complete
	version != ""
	not spec(version)
}

# A standard no document this producer emits can satisfy.
violation contains {
	"rule": "manifest cover other",
	"verdict": "manifest check unread",
	"subjects": [{"path": pointer(sprintf("%s-needs-spdx3", [entry.name]))}],
} if {
	complete
	spec(version)
	some entry in standards
	entry.name in spdx3_only
	spec(version) != "spdx3"
}

# THE VERDICT: the checker refused the document under this standard.
violation contains {
	"rule": "manifest cover other",
	"verdict": "manifest cover partial",
	"subjects": [{"path": pointer(entry.name)}],
} if {
	complete
	some entry in standards
	entry.exit != "0"
}

# --- cases -------------------------------------------------------------------

record(spdx_version, entries) := {"tree": {"records": {"ntia": array.concat(
	["document\tbatten.spdx.json", sprintf("spdx-version\t%s", [spdx_version])],
	entries,
)}}}

found(given) := {sprintf("%s %s", [v.verdict, v.subjects[0].path]) |
	some v in violation with input as given
}

test_a_conforming_document_is_clean if {
	count(violation) == 0 with input as record("SPDX-2.3", ["standard\tntia\t0\t-"])
}

test_a_refused_standard_is_partial if {
	found(record("SPDX-2.3", ["standard\tntia\t1\tcomponents=3"])) == {"manifest cover partial batten.spdx.json#ntia"}
}

test_the_exit_code_decides_not_the_counts if {
	found(record("SPDX-2.3", ["standard\tntia\t1\tcomponents=3 no-supplier=0 no-license=0 no-copyright=0"])) == {"manifest cover partial batten.spdx.json#ntia"}
}

test_an_spdx3_only_standard_over_spdx2_is_unread if {
	found(record("SPDX-2.3", ["standard\tntia\t0\t-", "standard\tfsct3-min\t0\t-"])) == {"manifest check unread batten.spdx.json#fsct3-min-needs-spdx3"}
}

test_the_same_standard_over_spdx3_is_askable if {
	count(violation) == 0 with input as record("SPDX-3.0.1", ["standard\tntia\t0\t-", "standard\tfsct3-min\t0\t-"])
}

test_an_absent_spdx_version_is_unread if {
	found(record("", ["standard\tntia\t0\t-"])) == {"manifest check unread batten.spdx.json#spdx-version-absent"}
}

test_an_unclassifiable_spdx_version_is_unread if {
	found(record("SPDX-9.9", ["standard\tntia\t0\t-"])) == {"manifest check unread batten.spdx.json#spdx-version-unknown"}
}

test_a_record_with_no_standard_is_torn if {
	some v in violation with input as {"tree": {"records": {"ntia": ["document\tbatten.spdx.json", "spdx-version\tSPDX-2.3"]}}}
	v.verdict == "manifest check unread"
}

test_no_record_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}
