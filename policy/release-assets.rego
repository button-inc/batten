# A release carries one archive per target the dist matrix builds and every
# platform-independent asset the release job uploads (ported off
# `mise-tasks/release-assets-check.sh` under CLOUD-1717; the predicates are
# CLOUD-258's and CLOUD-262's).
#
# `release-artifacts.yml` failed on every release from v0.0.31 to v0.0.36 and no
# binary shipped, unnoticed, because a `release`-triggered run reaches no PR and no
# gate. This is that missing signal, run on a clock (`release-assets.yml`) because
# it is a property of the world rather than of a commit.
#
# THE SPLIT, SINCE CLOUD-843. `batten record release` records what the forge
# says — the tag, the assets, and the manifest's entries and byte failures — and
# the `release-hygiene` preset decides whether the manifest tells the truth
# about them. What is left HERE is the half only this repository can state:
# which assets a release of THIS project must carry. The body this replaced
# derived that list with `sed` and `awk` over the workflow and recorded it beside
# the release's facts; it is derived here now, from the workflow the rule row
# declares as a document, because a derivation from a committed file belongs
# where the file is already parsed.
#
# WHERE EACH EXPECTED NAME COMES FROM, one authority each:
#   * targets — every `target` in the workflow's matrix `include` list;
#   * a binary SBOM per leg whose `build-tool` is not `cross`, named by `dist`'s
#     stem rule over the RECORDED tag (`<bin>-<tag>-<target>.spdx.json`) — the
#     tag the release was cut from, where the retired body read the checkout's
#     version and misnamed every leg of an older tag;
#   * the literal `.json`/`.sh` operands of the workflow's `gh release upload`
#     lines, basenames only;
#   * the repository SBOM's two documents, which the sbom producer names;
#   * the CLI reference, whose name `mise.toml`'s `[env]` declares once.
#
# ARCHIVE, NOT TRIPLE: a composed leg also uploads `<stem>.spdx.json`, whose name
# carries the same triple, so a target is present only when an asset naming it
# ends in `.tar.gz` or `.zip` — the document must not stand in for the binary.
#
# COULD NOT LOOK IS A FINDING HERE, NEVER A PASS: a workflow that did not parse,
# a matrix naming no target, no upload line to read, an undeclared reference
# name, or a record carrying no tag each mean the list of what must ship is
# unknown, and a gate over an unknown list must not report a complete release.
# The retired body refused to record in each of those cases; the record is the
# forge's facts alone now, so the refusal moved to the one place that reads the
# list.
#
#MUTANT-SUITE crates/batten/tests/it/release_assets.rs
#MUTANT missing-archive-passes|s@^\tnot archived(target)$@\tfalse@|a_release_with_only_the_schema_is_refused
#MUTANT missing-extra-passes|s@^\tnot name in assets$@\tfalse@|every_non_target_asset_is_demanded_from_both_sources
#MUTANT unreadable-list-passes|s@^\tnot expectations_readable$@\tfalse@|a_list_that_cannot_be_derived_is_partial_never_complete

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

# The build workflow the expectations are read off, and the manifest that names
# the reference. Both are declared as documents on the rule row.
workflow_path := ".github/workflows/release-artifacts.yml"

# The repository SBOM's two documents, as the sbom producer names them.
sbom_documents := {"batten.spdx.json", "batten.cdx.json"}

# The binary name every per-target asset stem begins with (`dist`'s stem rule).
binary := "batten"

lines := input.tree.records["release-assets"]

of(kind) := {columns[1] |
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == kind
}

assets := of("release-asset")

tag := name if {
	tags := of("release-tag")
	count(tags) == 1
	some name in tags
}

workflow := input.tree.documents[workflow_path]

# Every matrix leg carrying a target, across every job.
legs contains leg if {
	is_object(workflow.jobs)
	some job in workflow.jobs
	some leg in job.strategy.matrix.include
	is_string(leg.target)
}

targets := {leg.target | some leg in legs}

# The legs that also publish a binary SBOM: a declared build tool that is not
# `cross`, as the release job's own `if:` reads it.
composed := {leg.target |
	some leg in legs
	is_string(leg["build-tool"])
	leg["build-tool"] != "cross"
}

# The literal operands of every `gh release upload` line, as basenames.
literal contains name if {
	some line in input.tree.lines[workflow_path]
	contains(line, "gh release upload")
	some token in split(line, " ")
	regex.match(data.batten.patterns["release-upload-operand"], token)
	parts := split(trim(token, "\""), "/")
	name := parts[count(parts) - 1]
}

reference := input.tree.documents["mise.toml"].env.BATTEN_CLI_REFERENCE

expectations_readable if {
	is_object(workflow)
	count(targets) > 0
	count(literal) > 0
	is_string(reference)
	tag
}

extras := ((literal | sbom_documents) | {reference}) | {sprintf("%s-%s-%s.spdx.json", [binary, tag, target]) | some target in composed}

archived(target) if {
	some name in assets
	contains(name, target)
	regex.match(data.batten.patterns["release-archive"], name)
}

violation contains {
	"rule": "release grade other",
	"verdict": "release read partial",
	"subjects": [{"path": workflow_path}],
} if {
	lines
	not expectations_readable
}

violation contains {
	"rule": "release grade other",
	"verdict": "release ship missing",
	"subjects": [{"artifact": target}],
} if {
	expectations_readable
	some target in targets
	not archived(target)
}

violation contains {
	"rule": "release grade other",
	"verdict": "release ship missing",
	"subjects": [{"artifact": name}],
} if {
	expectations_readable
	some name in extras
	not name in assets
}

# --- cases -------------------------------------------------------------------

fixture(record, workflow_lines) := {"tree": {
	"records": {"release-assets": record},
	"documents": {
		workflow_path: {"jobs": {"dist": {"strategy": {"matrix": {"include": [
			{"target": "x86_64-unknown-linux-gnu", "build-tool": "cargo"},
			{"target": "aarch64-unknown-linux-gnu", "build-tool": "cross"},
		]}}}}},
		"mise.toml": {"env": {"BATTEN_CLI_REFERENCE": "ref.md"}},
	},
	"lines": {workflow_path: workflow_lines},
}}

uploads := [`        run: gh release upload "$TAG" schema/batten.schema.json install.sh "$SPDX" --clobber`]

complete := [
	"release-tag\tv1.2.3",
	"release-asset\tbatten-v1.2.3-x86_64-unknown-linux-gnu.tar.gz",
	"release-asset\tbatten-v1.2.3-aarch64-unknown-linux-gnu.tar.gz",
	"release-asset\tbatten-v1.2.3-x86_64-unknown-linux-gnu.spdx.json",
	"release-asset\tbatten.schema.json",
	"release-asset\tinstall.sh",
	"release-asset\tbatten.spdx.json",
	"release-asset\tbatten.cdx.json",
	"release-asset\tref.md",
]

test_a_complete_release_is_clean if {
	count(violation) == 0 with input as fixture(complete, uploads)
		with data.batten.patterns as patterns
}

test_an_sbom_does_not_stand_in_for_an_archive if {
	found := violation with input as fixture(
		[line | some line in complete; not endswith(line, "x86_64-unknown-linux-gnu.tar.gz")],
		uploads,
	)
		with data.batten.patterns as patterns
	{entry.subjects[0].artifact | some entry in found} == {"x86_64-unknown-linux-gnu"}
}

test_a_cross_leg_publishes_no_binary_sbom if {
	# The `cross` leg's SBOM is never demanded, and the composed one is.
	found := violation with input as fixture(
		[line | some line in complete; not endswith(line, ".spdx.json"); line != "release-asset\tbatten.spdx.json"],
		uploads,
	)
		with data.batten.patterns as patterns
	{entry.subjects[0].artifact | some entry in found} == {
		"batten-v1.2.3-x86_64-unknown-linux-gnu.spdx.json",
		"batten.spdx.json",
	}
}

test_no_upload_line_is_partial if {
	found := violation with input as fixture(complete, ["        run: echo nothing"])
		with data.batten.patterns as patterns
	{entry.verdict | some entry in found} == {"release read partial"}
}

test_no_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}, "documents": {}, "lines": {}}}
		with data.batten.patterns as patterns
}

patterns := {
	"release-archive": `[.](tar[.]gz|zip)$`,
	"release-upload-operand": `^"?[A-Za-z0-9_./-]+[.](json|sh)"?$`,
}
