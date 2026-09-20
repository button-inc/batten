# THE INERT LIST IS THE WHOLE REVIEW SURFACE, so it gets a gate (CLOUD-398).
#
# `[ci] slow_inert` inverts the default: the hk slow tier runs unless EVERY
# changed path is covered, which means a wrong entry is the only way to lose a
# verdict. The retired `mise-tasks/ci-slow-needed.sh` knew that and answered it
# with a `--probe` mode inside itself, on the argument that a second program
# asserting things about its list would be the second authority non-negotiable 6
# condemns.
#
# THE LIST IS CONFIG NOW, so that argument no longer holds and reverses: the list
# is data this module READS, not a list it owns, so there is exactly one authority
# and it is `batten.toml`. What was a self-test is a gate over declared data,
# which is the shape the campaign exists to reach.
#
# BOTH DIRECTIONS, because each fails silently in its own way. A list that
# swallowed a live path loses a verdict — the tier is skipped and CI is green over
# a check nobody ran. A list that stopped covering an inert path costs a bill
# nobody sees, and erosion in that direction is invisible except as minutes. The
# probes below are the retired program's own, carried across unchanged.
#
# COULD-NOT-LOOK IS NOT CLEAN: an undeclared `[ci]` table, or one with no
# `slow_inert` key, means this module cannot see the list at all. It reports
# rather than passing, because a list nobody could read is not a list anybody
# reviewed.

#MUTANT-SUITE crates/batten/tests/it/ci_slow_needed.rs
#MUTANT ci-slow-inert|s@^\t"batten.toml",$@@|a_list_admitting_a_path_that_moves_the_tier_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ci_slow_inert

import rego.v1

rules contains "path list loose"

# The declared list, or undefined when the authority does not carry one.
declared := input.tree.documents["batten.toml"].ci.slow_inert

# Whether `path` is covered, by the same rule the engine applies: a trailing `/`
# covers a directory, anything else must match exactly.
covered(path) if {
	some entry in declared
	endswith(entry, "/")
	startswith(path, entry)
}

covered(path) if {
	some entry in declared
	not endswith(entry, "/")
	path == entry
}

# PATHS A CHANGE TO WHICH CAN MOVE ONE OF THE SIX SLOW STEPS. Treating any of
# these as inert loses a verdict silently.
must_move := {
	"crates/batten/src/lib.rs",
	"Cargo.lock",
	"batten.toml",
	"mise.toml",
	"bench/tokens/fixtures/x",
	".github/workflows/ci.yml",
	".claude/hooks/git-hook.sh",
	"AGENTS.md",
}

# AND THE HALF THAT PAYS FOR THE SPLIT. Without it the list can narrow to nothing
# and the only symptom is the bill.
must_be_inert := {".serena/memories/core.md", ".coderabbit.yaml"}

violation contains {
	"rule": "path list loose",
	"verdict": "path admit unsafe",
	"subjects": [{"path": path}],
} if {
	declared
	some path in must_move
	covered(path)
}

violation contains {
	"rule": "path list loose",
	"verdict": "path list dropped",
	"subjects": [{"path": path}],
} if {
	declared
	some path in must_be_inert
	not covered(path)
}

violation contains {
	"rule": "path list loose",
	"verdict": "config read unread",
	"subjects": [{"path": "batten.toml"}],
} if {
	not declared
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE and were owed from the commit that landed the module.
# `crates/batten/tests/it/ci_slow_needed.rs` is the tier that proves the ENGINE
# builds `input.tree.documents["batten.toml"]` with a `ci.slow_inert` array at
# all -- a `with input as` case fabricates the very shape the engine may be
# unable to produce, which is how a dead clause survives a green suite.
#
# BOTH DIRECTIONS ARE EXERCISED, because a one-sided suite cannot see the failure
# that costs money. A list that admits a live path loses a verdict silently; a
# list narrowed to nothing loses only the saving, and its only symptom is the
# bill.

authority(entries) := {"tree": {"documents": {"batten.toml": {"ci": {"slow_inert": entries}}}}}

# The list this repository actually ships.
landed := [".serena/memories/", ".coderabbit.yaml"]

test_the_landed_list_is_clean if {
	count(violation) == 0 with input as authority(landed)
}

# A DIRECTORY ENTRY COVERS ITS CONTENTS and an exact entry does not cover a
# prefix, which is the engine's own rule restated here so a change to either side
# reddens rather than diverges quietly.
test_a_directory_entry_covers_what_is_under_it if {
	count(violation) == 0 with input as authority([".serena/memories/", ".coderabbit.yaml"])
}

test_an_entry_without_a_slash_must_match_exactly if {
	findings := violation with input as authority([".serena/memories", ".coderabbit.yaml"])
	some finding in findings
	finding.verdict == "path list dropped"
}

# THE OVER-DENY DIRECTION: a list wide enough to swallow a path that can move the
# tier is the failure with no symptom, so it is named by the path it admits.
test_a_list_admitting_the_engine_source_is_refused if {
	findings := violation with input as authority(["crates/", ".serena/memories/", ".coderabbit.yaml"])
	some finding in findings
	finding.verdict == "path admit unsafe"
	finding.subjects[0].path == "crates/batten/src/lib.rs"
}

test_a_list_admitting_the_authority_itself_is_refused if {
	findings := violation with input as authority(["batten.toml", ".serena/memories/", ".coderabbit.yaml"])
	some finding in findings
	finding.verdict == "path admit unsafe"
}

test_a_list_admitting_the_workflow_is_refused if {
	findings := violation with input as authority([".github/", ".serena/memories/", ".coderabbit.yaml"])
	some finding in findings
	finding.verdict == "path admit unsafe"
}

# THE UNDER-DENY DIRECTION: an empty list is legal TOML and buys nothing, and
# nothing else in the set would say so.
test_an_empty_list_is_refused_for_what_it_no_longer_covers if {
	findings := violation with input as authority([])
	some finding in findings
	finding.verdict == "path list dropped"
}

# COULD-NOT-LOOK IS ITS OWN CLASS. An authority carrying no list at all is not a
# list that covers nothing: the remedy is to declare one, and reporting it as a
# narrow list would send the reader to widen something that is not there.
test_an_authority_with_no_list_is_could_not_look if {
	findings := violation with input as {"tree": {"documents": {"batten.toml": {}}}}
	some finding in findings
	finding.verdict == "config read unread"
}

test_an_unreadable_authority_is_could_not_look_too if {
	findings := violation with input as {"tree": {"documents": {}}}
	some finding in findings
	finding.verdict == "config read unread"
}
