# METADATA
# description: |
#   The successor shape for the `released` family, and the demonstration
#   CLOUD-1200 owes: a tree-scoped module deciding over a set no declaration can
#   enumerate.
#
#   `released.sh` walks `git tag` to decide what has shipped, and
#   `release-due`, `release-backfill`, `release-tracking-check` and
#   `landed-check` read the same shape. None of them could migrate, because
#   `input.tree["git-refs"]` resolves what a rule NAMES and which tags exist is
#   not knowable when the row is written. `input.tree["git-history"]` is the half
#   that resolves a PATTERN instead.
#
#   THE PREDICATE IS THIS CONSUMER'S, NOT THE ENGINE'S. A release tag's spelling
#   is this repository's vocabulary — `release-plz` mints `v<major>.<minor>.<patch>`
#   — and non-negotiable rule 1 keeps that out of `crates/batten`. So the engine
#   supplies "every tag matching `v*`" and this module decides what a matching
#   tag must look like.
#
#   NULL IS THE COMMON CASE HERE and the guard is not defensive style: this
#   family answers could-not-look for a SHALLOW clone, `linear-check` deepens one
#   before it can answer, and this repository's own working copy carries
#   `.git/shallow`. `some .. in null` is a hard evaluation FAULT in Rego rather
#   than a silent miss, so a module that iterates this key unguarded takes its
#   whole bundle down on exactly the checkout it will most often meet. Measured
#   while writing `crates/batten/tests/history_facts.rs`, where it did.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_tag_shape

import rego.v1

rules contains "release-tag-shape"

# Every tag the declared glob matched.
#
# GUARDED, per the header: the key is `null` on a shallow clone and iterating a
# null faults the bundle rather than holding.
shipped contains tag if {
	is_object(input.tree["git-history"])
	some entry in input.tree["git-history"]["release-tags"]
	tag := entry.tag
}

violation contains {
	"rule": "release-tag-shape",
	"verdict": "tag mint wrong",
	"subjects": [{"count": count(malformed)}],
} if {
	count(malformed) > 0
}

malformed contains tag if {
	some tag in shipped
	not regex.match(data.batten.patterns["release-tag"], tag)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves a tag glob at
# all — a `with input as` case fabricates the very shape the engine may be unable
# to produce (CLOUD-845, CLOUD-857), and here it would fabricate the shallow
# distinction the family turns on. `crates/batten/tests/history_facts.rs` is that
# tier.

tags(names) := {"tree": {"git-history": {"release-tags": [
{"commit": "0000000", "subject": "s", "tag": name} |
	some name in names
]}}}

test_a_conventional_tag_is_clean if {
	count(violation) == 0 with input as tags({"v0.0.134"})
}

test_a_tag_missing_its_prefix_is_refused if {
	some v in violation with input as tags({"0.0.134"})
	v.verdict == "tag mint wrong"
}

test_a_tag_with_a_trailing_label_is_refused if {
	some v in violation with input as tags({"v0.0.134-rc1"})
	v.verdict == "tag mint wrong"
}

test_no_tags_is_clean if {
	count(violation) == 0 with input as tags(set())
}

# THE COULD-NOT-LOOK ARM, and the one a shallow checkout meets. Without the
# `is_object` guard this case does not merely fail — it faults.
test_a_shallow_clone_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"git-history": null}}
}

#MUTANT-SUITE crates/batten/tests/it/history_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree["git-history"]` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT malformed-tag-unread|s@^\tcount(malformed) > 0$@\tfalse@|a_declared_tag_glob_resolves_its_matching_set
