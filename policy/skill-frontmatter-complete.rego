# METADATA
# description: |
#   Every shipped skill declares the two fields a harness needs to load it, and
#   declares a name that matches where it lives.
#
#   WHY A GATE AND NOT A CONVENTION (CLOUD-1787). A skill's `name` and
#   `description` are the entire basis on which a harness decides whether to
#   load it. A skill missing either does not fail loudly — it is simply never
#   selected, which is indistinguishable from a skill that was selected and had
#   nothing to say. That is the same silence class this repository's whole fact
#   model is built against, one layer out, and until frontmatter was parseable
#   nothing here could read the fields to check them.
#
#   `name` MUST EQUAL THE DIRECTORY, which is the clause worth stating. The two
#   are separate authorities today: a harness routes by directory and displays
#   by `name`, so a skill whose fields disagree with its path is invoked under
#   one identity and reads under another. Asserting agreement collapses them to
#   one without either side having to stop existing.
#
#   THE PREDICATE IS THIS CONSUMER'S. `SKILL.md`, `name` and `description` are
#   an agent harness's vocabulary and this repository's layout; the engine
#   supplies a parsed frontmatter node keyed by path and knows neither.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.skill_frontmatter_complete

import rego.v1

rules contains "prompt declare partial"

# A field is absent, or present and blank.
#
# Blank counts, and the distinction is load-bearing: `name:` with nothing after
# it parses to a null and `name: ""` parses to an empty string, so a predicate
# testing only for the KEY passes both — a skill that declares its fields and
# fills in neither.
violation contains {
	"rule": "prompt declare partial",
	"verdict": "prompt declare missing",
	"subjects": [{"path": path}],
} if {
	some path, document in input.tree.documents
	some field in ["name", "description"]
	not stated(document[field])
}

stated(value) if {
	is_string(value)
	trim_space(value) != ""
}

# The declared name and the directory it ships in disagree.
violation contains {
	"rule": "prompt declare partial",
	"verdict": "prompt name wrong",
	"subjects": [{"path": path}],
} if {
	some path, document in input.tree.documents
	stated(document.name)
	document.name != directory_of(path)
}

# `skills/batten/SKILL.md` -> `batten`. The second-to-last segment, which is the
# skill's own directory whatever it is nested under.
directory_of(path) := segment if {
	segments := split(path, "/")
	count(segments) > 1
	segment := segments[count(segments) - 2]
}

# Read and refused, or carrying no frontmatter at all. Both are a skill this
# module could not judge, and both refuse rather than report clean: a `SKILL.md`
# with no fence declares no fields, which is the violation above arriving
# through the acquisition layer instead of through the document.
violation contains {
	"rule": "prompt declare partial",
	"verdict": "prompt read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. The ENGINE half — that a `SKILL.md` reaches
# `input.tree.documents` as a parsed frontmatter node at all — is
# `crates/batten/tests/it/frontmatter_gates.rs`, over the compiled binary.

skill(fields) := {"tree": {
	"documents": {"skills/batten/SKILL.md": fields},
	"missing": {},
}}

test_a_complete_skill_is_clean if {
	count(violation) == 0 with input as skill({"name": "batten", "description": "what it does"})
}

test_a_skill_missing_its_description_is_refused if {
	some v in violation with input as skill({"name": "batten"})
	v.verdict == "prompt declare missing"
}

# Blank is absent. `name:` with nothing after it parses to a null and `name: ""`
# to an empty string, and a predicate testing only for the KEY passes both.
test_a_blank_field_is_refused_like_an_absent_one if {
	some v in violation with input as skill({"name": "   ", "description": "d"})
	v.verdict == "prompt declare missing"
}

test_a_null_field_is_refused_like_an_absent_one if {
	some v in violation with input as skill({"name": null, "description": "d"})
	v.verdict == "prompt declare missing"
}

test_a_name_disagreeing_with_its_directory_is_refused if {
	some v in violation with input as skill({"name": "serena", "description": "d"})
	v.verdict == "prompt name wrong"
}

# A skill nested deeper still resolves to its OWN directory rather than the tree
# it hangs under, which is what makes the same rule cover both roots.
test_a_nested_skill_resolves_its_own_directory if {
	count(violation) == 0 with input as {"tree": {
		"documents": {".claude/skills/batten/SKILL.md": {"name": "batten", "description": "d"}},
		"missing": {},
	}}
}

test_a_skill_that_could_not_be_read_is_refused if {
	some v in violation with input as {"tree": {
		"documents": {},
		"missing": {"skills/batten/SKILL.md": "no-document"},
	}}
	v.verdict == "prompt read unread"
}

#MUTANT-SUITE crates/batten/tests/it/frontmatter_gates.rs
#MUTANT blank-field-admitted|s@\tnot stated(document\[field\])$@\tfalse@|a_skill_missing_a_declared_field_is_refused
