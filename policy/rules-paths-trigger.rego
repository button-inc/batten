# METADATA
# description: |
#   Every rule stub in the vendor-specific directory carries the loading trigger
#   that is its only reason to exist.
#
#   THE FINDING THAT MOTIVATED IT (CLOUD-1787, CLOUD-1152). This repository's
#   doctrine lives at the root, neutral, because five of the six harnesses
#   Batten adjudicates for cannot read a vendor directory. What stays in the
#   vendor directory is a stub, and the stub is kept for ONE thing: the
#   frontmatter trigger, which is a loading mechanism no neutral location has.
#   Its own body says so — "deleting this file would cost that trigger."
#
#   One of those stubs never had the trigger. Not lost in an edit: absent from
#   the commit that wrote the claim, and absent every day since, while the file
#   asserted otherwise in prose and four siblings carried it correctly. Nothing
#   could see that, because nothing could read frontmatter — a stub with no
#   trigger and a stub with one are byte-identical to every gate this repository
#   had. That is the whole class: a claim about the tree that the tree refutes,
#   surviving because the mechanism to check it did not exist.
#
#   THE COULD-NOT-LOOK ARM DENIES HERE RATHER THAN ABSTAINING, and that is the
#   arm the live finding actually exercises. `no-document` means the file was
#   read in full and has no frontmatter at all, which for this rule is not an
#   inability to judge — it IS the violation, stated by the acquisition layer
#   instead of by this module. Reporting it as could-not-look would be the
#   vacuous pass arriving through the honest channel.
#
#   THE PREDICATE IS THIS CONSUMER'S. That a rule stub declares `paths:` is
#   Claude Code's convention and this repository's use of it; the engine supplies
#   a parsed frontmatter node and knows nothing about either.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.rules_paths_trigger

import rego.v1

rules contains "prose carry missing"

# The fence is there and carries no `paths:`, or carries an empty one.
#
# Empty is a violation and not a skip: a stub declaring `paths: []` fires on
# nothing, which is the same outcome as having no trigger and reached by a
# different authoring mistake. The acquisition layer keeps the two apart —
# an empty FENCE is a document with no keys and lands here, a missing fence
# lands in `missing` below — so both are decided rather than one silently
# standing in for the other.
violation contains {
	"rule": "prose carry missing",
	"verdict": "prose declare missing",
	"subjects": [{"path": path}],
} if {
	some path, document in input.tree.documents
	not triggers_on_something(document)
}

triggers_on_something(document) if {
	count(document.paths) > 0
}

# No frontmatter at all. Its own verdict rather than folded into the arm above,
# because the remedy differs: one says fix the trigger you wrote, this says you
# wrote none.
violation contains {
	"rule": "prose carry missing",
	"verdict": "prose declare missing",
	"subjects": [{"path": path}],
} if {
	some path, cause in input.tree.missing
	cause == "no-document"
}

# Read and refused. A stub whose fence will not parse is one this module could
# not judge, and a refusal is the only honest answer: iterating only the files
# that parsed reports green over the one it never saw.
violation contains {
	"rule": "prose carry missing",
	"verdict": "prose read unread",
	"subjects": [{"path": path}],
} if {
	some path, cause in input.tree.missing
	cause in {"unparsed", "unreadable", "unknown-format"}
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE parses a markdown
# file's frontmatter at all — a `with input as` case fabricates the very shape
# the engine may be unable to produce (CLOUD-845, CLOUD-857), and here that
# shape is the whole new thing: `input.tree.documents` holding a node read out
# of a `.md`, and `missing` carrying `no-document` rather than `unparsed`.
# `crates/batten/tests/it/frontmatter_gates.rs` is that tier, over the compiled
# binary and a real tree.

stub(paths) := {"tree": {
	"documents": {".claude/rules/x.md": {"paths": paths}},
	"missing": {},
}}

unread(cause) := {"tree": {
	"documents": {},
	"missing": {".claude/rules/x.md": cause},
}}

test_a_stub_with_a_trigger_is_clean if {
	count(violation) == 0 with input as stub(["crates/**/*.rs"])
}

test_a_stub_with_an_empty_trigger_is_refused if {
	some v in violation with input as stub([])
	v.verdict == "prose declare missing"
}

test_a_stub_with_no_trigger_key_is_refused if {
	some v in violation with input as {"tree": {
		"documents": {".claude/rules/x.md": {"title": "x"}},
		"missing": {},
	}}
	v.verdict == "prose declare missing"
}

# THE MEASURED CASE. A stub with no fence at all reaches the module through
# `missing`, under its own cause, and must deny rather than abstain — the file
# exists, it was read in full, and the trigger it claims to carry is not there.
test_a_stub_with_no_frontmatter_is_refused_and_not_merely_unread if {
	some v in violation with input as unread("no-document")
	v.verdict == "prose declare missing"
}

# And the two causes do not collapse: a fence that will not parse is a different
# verdict, because the author's next move is different.
test_a_stub_whose_fence_will_not_parse_is_unread if {
	some v in violation with input as unread("unparsed")
	v.verdict == "prose read unread"
}

test_no_stubs_at_all_is_clean if {
	count(violation) == 0 with input as {"tree": {"documents": {}, "missing": {}}}
}

#MUTANT-SUITE crates/batten/tests/it/frontmatter_gates.rs
#MUTANT trigger-absent-unread|s@\tnot triggers_on_something(document)$@\tfalse@|a_rules_stub_without_a_paths_trigger_is_refused
