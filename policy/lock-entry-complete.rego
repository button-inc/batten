# METADATA
# description: |
#   The successor shape for `lock-complete`, and the demonstration CLOUD-1203
#   unit A owes: a tree-scoped module deciding over the git INDEX rather than the
#   working tree.
#
#   THE INDEX IS THE WHOLE POINT. `lock-complete` is the pure "committed bytes
#   only, no network, no write" gate — it judges THE COMMIT, not the developer's
#   working copy — so a successor reading `input.tree.documents` would answer a
#   different question and pass over a staged-but-unsaved edit. That is a silent
#   wrong answer, not a missing feature, and `input.tree.staged` is the only key
#   in the model that can avoid it: `Fact::Tracked` walks the checkout and says
#   so in its own doc, and `Fact::GitStatus` carries paths and a count.
#
#   THE PREDICATE IS THE ONE `lock-complete`'s OWN COMMENT CITES as its
#   motivation: a platform entry carrying a checksum and no url. Such an entry is
#   the partial shape a regenerate-and-diff gate structurally cannot catch,
#   because `mise lock` never removes or repairs an existing entry — so a stably
#   wrong lockfile passes forever, and one did.
#
#   WHAT THIS DELIBERATELY IS NOT is the currency question. Whether upstream has
#   moved since this commit is a property of the WORLD and belongs on a schedule;
#   this is a property of the COMMIT and belongs in a gate. `lock-complete`'s own
#   split records that lesson, and reading the index rather than the network is
#   what keeps this half on the right side of it.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.lock_entry_complete

import rego.v1

rules contains "lock-entry-complete"

# Every platform entry in the STAGED lockfile.
#
# `[[tools."x"]]` is an array of tables and `[tools."x"."platforms.y"]` addresses
# the last element of it, so the parsed shape is a list per tool whose entries
# carry `version`, `backend` and one key per platform. The `startswith` is what
# separates the platform sub-tables from those two scalars.
platforms contains platform if {
	some entries in input.tree.staged["mise.lock"].tools
	some entry in entries
	some key, platform in entry
	startswith(key, "platforms.")
}

# A checksum with nothing to fetch.
#
# The pair is the point: an entry with neither is simply unlocked, and an entry
# with both is complete. One without the other is the partial shape that reads as
# locked and cannot be used.
violation contains {
	"rule": "lock-entry-complete",
	"verdict": "lock write partial",
	"subjects": [{"path": "mise.lock"}, {"count": count(partial)}],
} if {
	count(partial) > 0
}

partial contains platform if {
	some platform in platforms
	platform.checksum
	not platform.url
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE reads the INDEX rather
# than the checkout — a `with input as` case fabricates the very shape the engine
# may be unable to produce, and here it would fabricate the very distinction the
# family exists for. `crates/batten/tests/staged_facts.rs` is that tier, and its
# `the_index_answers_not_the_worktree` case is the one that discriminates.

lock(entry) := {"tree": {"staged": {"mise.lock": {"tools": {"aqua:example/tool": [entry]}}}}}

complete := {
	"version": "1.0.0",
	"backend": "aqua:example/tool",
	"platforms.linux-x64": {"checksum": "sha256:abc", "url": "https://example.invalid/tool.tar.gz"},
}

test_a_complete_entry_is_clean if {
	count(violation) == 0 with input as lock(complete)
}

test_a_checksum_with_no_url_is_refused if {
	some v in violation with input as lock({
		"version": "1.0.0",
		"backend": "aqua:example/tool",
		"platforms.linux-x64": {"checksum": "sha256:abc"},
	})
	v.verdict == "lock write partial"
}

test_an_unlocked_entry_is_not_a_partial_one if {
	count(violation) == 0 with input as lock({
		"version": "1.0.0",
		"backend": "aqua:example/tool",
		"platforms.linux-x64": {},
	})
}

# The two scalars beside the platform tables must not be read as platforms, or a
# tool whose `backend` happens to be a map would be judged as one.
test_version_and_backend_are_not_platforms if {
	count(violation) == 0 with input as lock({"version": "1.0.0", "backend": "aqua:example/tool"})
}

#MUTANT-SUITE crates/batten/tests/it/staged_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree.staged` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT partial-entry-unread|s@^\tcount(partial) > 0$@\tfalse@|the_index_answers_not_the_worktree
