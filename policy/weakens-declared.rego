# METADATA
# description: |
#   The successor shape for `config-lint.sh:174`, and the demonstration
#   CLOUD-1187 owes.
#
#   That program reads `git log --format='%(trailers:key=Weakens,valueonly)'
#   origin/main..HEAD` to learn which weakenings an author DECLARED, and compares
#   them against the ones `trust::weakenings` DETECTED. It is why CLOUD-1162's
#   unit 15 could not land: `input.tree["git-ranges"]` carries a sha and a
#   subject, so a trailer had no surface at all.
#
#   This module is the narrow half — whether a declaration says anything. A
#   `Weakens:` trailer with nothing after the colon is a declaration that names
#   no key, which reads to every downstream comparison as "the author declared
#   something" while matching no detected weakening. That is the shape a reviewer
#   cannot see and a gate can.
#
#   THE COMPARISON ITSELF STAYS OUT. Deciding whether a declared key matches a
#   detected one needs `trust::weakenings`' own output, which is not a fact; that
#   half is CLOUD-1162's port and not this row's. What this row proves is that
#   the trailer is READABLE over a declared range, which is the thing that was
#   impossible before.
#
#   NO MESSAGE BODY IS AVAILABLE HERE and that is deliberate: `git::CommitMeta`
#   has no such field, so non-negotiable rule 4 is decided by the type rather
#   than by this module's restraint. A predicate wanting the body does not
#   migrate and keeps its verb.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.weakens_declared

import rego.v1

rules contains "weakens-declared"

# Every `Weakens:` trailer on every commit in every declared range.
#
# Ranges are iterated rather than named: which range this row declares is
# `batten.toml`'s business, and a module naming one would be a second authority
# over the same declaration.
weakens contains value if {
	some commits in input.tree["commit-meta"]
	some entry in commits
	some trailer in entry.trailers
	startswith(trailer, "Weakens:")
	value := trim_space(substring(trailer, count("Weakens:"), -1))
}

violation contains {
	"rule": "weakens-declared",
	"verdict": "V-WEAKENS-DECLARES-NOTHING",
	"subjects": [{"count": count(empty)}],
} if {
	count(empty) > 0
}

empty contains value if {
	some value in weakens
	value == ""
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree["commit-meta"]` at all — a `with input as` case fabricates the very
# shape the engine may be unable to produce (CLOUD-845, CLOUD-857) — which is why
# `crates/batten/tests/commit_meta_facts.rs` exists over the compiled binary.

range(trailers) := {"tree": {"commit-meta": {"origin/main..HEAD": [{
	"commit": "0000000",
	"author": "A <a@example.com>",
	"committer": "A <a@example.com>",
	"trailers": trailers,
}]}}}

test_a_declared_key_is_clean if {
	count(violation) == 0 with input as range(["Weakens: protected"])
}

test_a_trailer_naming_nothing_is_refused if {
	some v in violation with input as range(["Weakens:"])
	v.verdict == "V-WEAKENS-DECLARES-NOTHING"
}

test_whitespace_is_not_a_declaration if {
	some v in violation with input as range(["Weakens:   "])
	v.verdict == "V-WEAKENS-DECLARES-NOTHING"
}

test_an_unrelated_trailer_is_ignored if {
	count(violation) == 0 with input as range(["Refs: CLOUD-1187"])
}

test_a_commit_with_no_trailers_is_clean if {
	count(violation) == 0 with input as range([])
}

#MUTANT-EXEMPT CLOUD-931|no `tests/weakens-declared.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `V-SHELL-RULE-ADDED` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/commit_meta_facts.rs`, neither of which is what the mutation runner drives
