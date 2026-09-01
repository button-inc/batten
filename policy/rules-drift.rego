#MUTANT-EXEMPT CLOUD-1267|the predecessor's `#MUTANT` rows re-home as `// carried:` case arms in crates/batten/tests/rules_drift.rs, which is the landed convention for a .rego successor (policy/ci-parity.rego, policy/harness-grant.rego, policy/claim-before-code.rego all carry one exemption and no rows).

# METADATA
# description: |
#   A value `.claude/rules/*.md` (and `.serena/memories/**`) restates still
#   agrees with the mechanism that owns it — CLOUD-506, CLOUD-770, CLOUD-932,
#   ported from `mise-tasks/rules-drift.sh` under CLOUD-843/CLOUD-1150.
#
#   WHAT THIS MUST NOT DO, and it is the sharper half of the design: demand that
#   a value be restated. `.claude/rules/toolchain.md`'s own rule is the opposite,
#   and a gate pushing toward completeness would invert the discipline it
#   enforces. Every predicate here fails a claim that is PRESENT AND WRONG, never
#   one that is absent.
#
#   THE AUTHORITY IS NEVER A LIST HERE. Predicate 1 reads `${VAR:-N}` out of the
#   programs themselves, 2 reads `.claude/settings.json`, 3 reads the GENERATED
#   schemas (`derived-check` diffs them byte-for-byte against the fact model, so
#   they cannot drift from what the engine emits without going red first), and 4
#   reads `policy.rs`'s own constants. A hand-written table in this file would be
#   the third authority this gate exists to refuse.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.rulesdrift

import rego.v1

rules contains "restated-default-drifts"

rules contains "named-event-unwired"

rules contains "named-input-key-unemittable"

rules contains "named-fixed-rule-unqueried"

rules contains "drift-authority-unreadable"

# --- the prose surfaces -------------------------------------------------------
#
# TWO of them, and the second is CLOUD-770's: `.serena/memories/**` is the
# largest prose surface in the repo and was subject to no predicate at all before
# it was added, because `memories-check` gates the graph's EDGES and deliberately
# not content. Its coverage is PROSPECTIVE — measured 2026-08-20, no memory uses
# the anchor — which is the honest claim for it rather than a catch count.
#
# A glob that matches nothing is silent here, where the predecessor exited 1 on
# an empty `$rules`. That difference is deliberate and is `drift-authority-
# unreadable` below: a declared AUTHORITY that cannot be read is a finding, and a
# prose surface with nothing in it is an ordinary consumer rather than a fault.
prose_lines[path] := lines if {
	some path, lines in input.tree.lines
	endswith(path, ".md")
}

# --- predicate 1: a restated env default must match ---------------------------
#
# The construction is `` `VAR` (N) `` — a backticked SHOUTY name immediately
# followed by a parenthesised number. Anchored on that PAIR rather than on the
# name alone, so prose naming a knob without asserting a value is untouched; that
# is the case that keeps the gate from inverting the rule.
restated contains {"path": path, "line": index + 1, "var": name, "claim": claim} if {
	some path, lines in prose_lines
	some index, text in lines
	some found in regex.find_n(data.batten.patterns["restated-default"], text, -1)
	halves := split(found, "` (")
	name := trim_prefix(halves[0], "`")
	claim := trim_suffix(halves[1], ")")
}

# Every `${VAR:-value}` any program spells, as [name, value] pairs.
#
# A pair rather than an object, because an object comprehension raises on a key
# with two values and the same knob may be read with a default in more than one
# program. The predecessor took `head -n1` of grep order; this asks whether the
# claim matches ANY observed default, which is strictly the more conservative
# direction and is recorded as a `// changed:` arm rather than carried silently.
shell_defaults contains [name, value] if {
	some path, lines in input.tree.lines
	endswith(path, ".sh")
	some _, text in lines
	some found in regex.find_n(data.batten.patterns["shell-default"], text, -1)
	inner := trim_suffix(trim_prefix(found, "${"), "}")
	halves := split(inner, ":-")
	name := halves[0]
	value := concat(":-", array.slice(halves, 1, count(halves)))
}

# A variable no program reads with a default is NOT judged: there is nothing to
# disagree with, and inventing a disagreement there is the completeness pressure
# this gate must not apply.
observed(name) if {
	some [found, _] in shell_defaults
	found == name
}

violation contains {
	"rule": "restated-default-drifts",
	"verdict": "V-RESTATED-DEFAULT-DRIFTS",
	"subjects": [{"path": claim.path, "line": claim.line}],
} if {
	some claim in restated
	observed(claim.var)
	not agrees(claim)
}

agrees(claim) if {
	some [name, value] in shell_defaults
	name == claim.var
	value == claim.claim
}

# --- predicate 2: a named hook event must be wired ----------------------------
#
# SENTENCE-scoped inside a paragraph, and keyed on the assertion rather than on
# the name. A rules file must stay able to say an event is NOT wired — CLOUD-461
# was the motivating instance, and its closing changed nothing, because the next
# accepted gap needs the same room. What cannot stand is the assertion that a
# task RUNS on an event nothing wires it to.
#
# The harness's event vocabulary. A backticked word outside it is ordinary prose:
# the gate judges event names and cannot be made to judge every capitalised token
# that happens to sit in a "runs on" paragraph. This IS a list, and it is the one
# thing here that is not read from a mechanism — the harness's vocabulary has no
# file in this repository to read it from, which is stated rather than hidden.
known_events := {
	"SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse",
	"PostToolUse", "PostToolBatch", "Stop", "SubagentStop", "Notification",
	"PreCompact",
}

blank(path, index) if {
	trim_space(prose_lines[path][index]) == ""
}

# The first line of the paragraph containing `index`.
#
# ANCHORED ON A "runs on" LINE rather than computed for every line, which is what
# keeps this affordable: the predecessor grouped every paragraph in every file
# and then discarded all but the ones carrying the claim.
paragraph_start(path, index) := start if {
	opens := [open |
		some before, _ in prose_lines[path]
		before < index
		blank(path, before)
		open := before + 1
	]
	start := max(array.concat(opens, [0]))
}

paragraph_end(path, index) := end if {
	closes := [close |
		some after, _ in prose_lines[path]
		after > index
		blank(path, after)
		close := after - 1
	]
	last := count(prose_lines[path]) - 1
	end := min(array.concat(closes, [last]))
}

# One entry per sentence that CLAIMS a wiring, carrying the paragraph it came
# from so the pointer can name the line a reader has to edit.
wiring_claims contains {"path": path, "start": start, "end": end, "sentence": sentence} if {
	some path, lines in prose_lines
	some index, text in lines
	contains(text, "runs on")
	start := paragraph_start(path, index)
	end := paragraph_end(path, index)
	body := concat(" ", [lines[at] | some at, _ in lines; at >= start; at <= end])

	# Split on `. `; a code span's dots (`mise.toml`, `.claude/settings.json`)
	# carry no following space and survive intact.
	some sentence in split(body, ". ")
	contains(sentence, "runs on")
}

# `.claude/settings.json`'s own `hooks` keys — the authority, read rather than
# restated.
wired_events contains name if {
	some name, _ in input.tree.documents[".claude/settings.json"].hooks
}

settings_readable if {
	some _, _ in input.tree.documents[".claude/settings.json"].hooks
}

# The line inside the paragraph that actually carries the token. A bullet list
# wraps into one paragraph, and its start can be dozens of lines above the name.
event_pointer(claim, name) := line if {
	hits := [hit |
		some at, text in prose_lines[claim.path]
		at >= claim.start
		at <= claim.end
		contains(text, sprintf("`%s`", [name]))
		hit := at + 1
	]
	line := min(hits)
}

violation contains {
	"rule": "named-event-unwired",
	"verdict": "V-NAMED-EVENT-UNWIRED",
	"subjects": [{"path": claim.path, "line": event_pointer(claim, name)}],
} if {
	some claim in wiring_claims
	some name in known_events
	contains(claim.sentence, sprintf("`%s`", [name]))
	settings_readable
	not wired(name)
}

wired(name) if {
	some found in wired_events
	found == name
}

# --- predicate 3: a named policy input key must be emittable ------------------
#
# CLOUD-932, and it exists because CLOUD-845 measured what an unemittable key
# costs: `policy.rs`'s own module doc — the example an author copies for their
# first module — iterated a key the engine did not build. Rego reads an undefined
# path as undefined, so the deny set was empty, and a dead gate and a clean tree
# were byte-identical. The loader refuses an unknown key in a MODULE now; prose
# naming one is still unjudged, and prose is what the next author reads first.
#
# Two surfaces, deliberately separate: the mediated document and the tree
# document are different shapes, and a key from the wrong one is that same silent
# dead gate wearing a plausible name.
schema_path := {
	"tree": "schema/policy-input.schema.json",
	"call": "schema/policy-call.schema.json",
}

# ONE FIXED PATH RATHER THAN A RECURSIVE DESCENT, and the difference is recorded
# rather than absorbed. The predecessor ran `jq '.. | objects | select(has("x"))'`
# because it could; measured against the generated files, each carries exactly one
# such node, at `properties.<surface>.properties`. This build of regorus has no
# `walk`, so the descent is not available — which makes the fixed path the only
# spelling, and makes the vacuity guard below load-bearing rather than tidy: a
# schema whose shape moved would yield NO keys here, and a predicate that reads
# zero keys reports every named key as unemittable, or none, depending on which
# way it is written. `drift-authority-unreadable` covers that as could-not-look.
schema_keys[surface] := keys if {
	some surface, path in schema_path
	keys := {key |
		some key, _ in input.tree.documents[path].properties[surface].properties
	}
	count(keys) > 0
}

# The schema was read and yielded nothing to compare against — a THIRD state,
# distinct from "read it and the key is absent" and from "could not read it".
schema_vacuous(surface) if {
	some found, path in schema_path
	found == surface
	not input.tree.documents[path]
}

schema_vacuous(surface) if {
	some found, _ in schema_path
	found == surface
	not schema_keys[surface]
}

named_keys contains {"path": path, "line": index + 1, "surface": surface, "key": key} if {
	some path, lines in prose_lines
	some index, text in lines
	some found in regex.find_n(data.batten.patterns["policy-input-key"], text, -1)
	trimmed := trim_prefix(found, "`input.")
	halves := split(trimmed, ".")
	surface := halves[0]
	key := halves[1]
}

violation contains {
	"rule": "named-input-key-unemittable",
	"verdict": "V-NAMED-INPUT-KEY-UNEMITTABLE",
	"subjects": [{"path": named.path, "line": named.line}],
} if {
	some named in named_keys
	some surface, keys in schema_keys
	surface == named.surface
	not keys[named.key]
}

# --- predicate 4: a named fixed rule must be one the evaluator queries --------
#
# CLOUD-932. The three rule names are the query root, so getting one wrong is the
# same silent class as an unemittable key: a module publishing `denies` instead
# of `deny` contributes nothing to the deny set without failing anything.
#
# ANCHORED ON THE CLOSING BACKTICK, which is what keeps `patterns` out: the
# pattern table is always written subscripted — `data.batten.patterns["<id>"]` —
# so it carries a bracket before the backtick and is not a bare rule reference.
# That is deliberate rather than incidental; a bare `data.batten.patterns` IS a
# name the evaluator does not query as a rule, and saying so is the honest report.
queried_rules contains name if {
	some _, text in input.tree.lines["crates/batten/src/policy.rs"]
	some found in regex.find_n(data.batten.patterns["policy-rule-const"], text, -1)
	name := split(found, "\"")[1]
}

named_rules contains {"path": path, "line": index + 1, "name": name} if {
	some path, lines in prose_lines
	some index, text in lines
	some found in regex.find_n(data.batten.patterns["fixed-rule-ref"], text, -1)
	name := trim_suffix(trim_prefix(found, "`data.batten."), "`")
}

violation contains {
	"rule": "named-fixed-rule-unqueried",
	"verdict": "V-NAMED-FIXED-RULE-UNQUERIED",
	"subjects": [{"path": named.path, "line": named.line}],
} if {
	some named in named_rules
	count(queried_rules) > 0
	not queried_rules[named.name]
}

# --- could-not-look -----------------------------------------------------------
#
# THE ARM THE PREDECESSOR SPELLED AS FOUR `exit 1` GUARDS, and the shape is the
# one difference worth stating. Those guards fired unconditionally at startup, so
# a checkout without `.claude/settings.json` was a wall of findings about prose
# nobody had written yet. Here the arm is conditioned on there being a CLAIM to
# judge: an unreadable authority is a finding exactly when some prose depends on
# it, which is what keeps a `[[rule]]` — a row with no call site, run wherever
# `batten check` runs — from speaking in every fixture repository that inherits
# this config. That scoping is Finding 7's class from `tree-clean`, avoided here
# rather than survived.
authority_needed contains path if {
	some _ in wiring_claims
	path := ".claude/settings.json"
}

authority_needed contains path if {
	some named in named_keys
	path := schema_path[named.surface]
}

authority_needed contains "crates/batten/src/policy.rs" if {
	some _ in named_rules
}

# ABSENCE IS READ FROM THE DOCUMENT MAP, NOT FROM `input.tree.missing`, and the
# reason is measured rather than stylistic. `missing` is never populated for
# either channel this row declares: a source the engine cannot read stops the
# WHOLE RULE from evaluating, so an arm reading `missing` is unreachable by
# construction and its absence is indistinguishable from a clean tree. The glob
# form of `sources` is what keeps the rule alive across an absent file, and the
# key simply not being in `documents` is then the honest signal.
violation contains {
	"rule": "drift-authority-unreadable",
	"verdict": "V-DRIFT-AUTHORITY-UNREADABLE",
	"subjects": [{"path": path}],
} if {
	some path in authority_needed
	endswith(path, ".json")
	not input.tree.documents[path]
}

# AND THE READ-BUT-EMPTY ARM. A schema whose shape moved is not in `missing` —
# the document parsed fine — so the channel above cannot see it, and every key
# named in prose would silently stop being judged. That is the vacuity the fixed
# path above buys, paid for here rather than left implicit.
violation contains {
	"rule": "drift-authority-unreadable",
	"verdict": "V-DRIFT-AUTHORITY-UNREADABLE",
	"subjects": [{"path": schema_path[named.surface]}],
} if {
	some named in named_keys
	schema_vacuous(named.surface)
}

# --- the load-time tier -------------------------------------------------------
#
# It pins each predicate. It CANNOT pin that the engine builds the input each one
# reads — `crates/batten/tests/rules_drift.rs` over the compiled binary is that
# tier, and it is where the anti-vacuity mirrors that matter live.

test_a_restated_default_that_disagrees_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {
			"a.md": ["the cap is `MAX_LAPS` (8) laps"],
			"t.sh": ["laps=\"${MAX_LAPS:-2}\""],
		},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "restated-default-drifts"
}

test_a_restated_default_that_agrees_is_not if {
	count({v | some v in violation; v.rule == "restated-default-drifts"}) == 0 with input as {"tree": {
		"lines": {
			"a.md": ["the cap is `MAX_LAPS` (2) laps"],
			"t.sh": ["laps=\"${MAX_LAPS:-2}\""],
		},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

# THE ANTI-INVERSION MIRROR, and it is the one this gate cannot ship without: a
# knob named with no value asserted must be untouched, because demanding the
# value be restated is the discipline this gate would otherwise invert.
test_a_knob_named_without_a_value_is_untouched if {
	count({v | some v in violation; v.rule == "restated-default-drifts"}) == 0 with input as {"tree": {
		"lines": {
			"a.md": ["the cap is `MAX_LAPS`, read it there"],
			"t.sh": ["laps=\"${MAX_LAPS:-2}\""],
		},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

test_a_variable_no_program_defaults_is_untouched if {
	count({v | some v in violation; v.rule == "restated-default-drifts"}) == 0 with input as {"tree": {
		"lines": {"a.md": ["the cap is `MAX_LAPS` (8) laps"], "t.sh": ["true"]},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

test_an_unwired_event_a_sentence_claims_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {"a.md": ["the guard runs on `PostToolBatch` today"]},
		"documents": {".claude/settings.json": {"hooks": {"PreToolUse": []}}},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "named-event-unwired"
}

test_a_wired_event_is_not if {
	count({v | some v in violation; v.rule == "named-event-unwired"}) == 0 with input as {"tree": {
		"lines": {"a.md": ["the guard runs on `PreToolUse` today"]},
		"documents": {".claude/settings.json": {"hooks": {"PreToolUse": []}}},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

# THE ROOM TO RECORD A GAP, and it is why the scope is a sentence rather than a
# paragraph: a paragraph stating a wiring often states an accepted gap in the
# same breath, and a paragraph-wide check would forbid the repo from writing its
# own gaps down beside the wiring they qualify.
test_a_gap_recorded_beside_a_wiring_is_untouched if {
	count({v | some v in violation; v.rule == "named-event-unwired"}) == 0 with input as {"tree": {
		"lines": {"a.md": [
			"the guard runs on `PreToolUse`. The `PostToolBatch` entry stays",
			"absent, and CLOUD-461 is why",
		]},
		"documents": {".claude/settings.json": {"hooks": {"PreToolUse": []}}},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

test_an_unemittable_tree_key_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {"a.md": ["a module iterates `input.tree.invented` here"]},
		"documents": {"schema/policy-input.schema.json": {"properties": {"tree": {"properties": {"documents": {}}}}}},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "named-input-key-unemittable"
}

test_an_emittable_tree_key_is_not if {
	count({v | some v in violation; v.rule == "named-input-key-unemittable"}) == 0 with input as {"tree": {
		"lines": {"a.md": ["a module iterates `input.tree.documents` here"]},
		"documents": {"schema/policy-input.schema.json": {"properties": {"tree": {"properties": {"documents": {}}}}}},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

test_an_unqueried_fixed_rule_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {
			"a.md": ["publish `data.batten.denies` to contribute"],
			"crates/batten/src/policy.rs": ["const DENY_RULE: &str = \"deny\";"],
		},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "named-fixed-rule-unqueried"
}

test_a_queried_fixed_rule_is_not if {
	count({v | some v in violation; v.rule == "named-fixed-rule-unqueried"}) == 0 with input as {"tree": {
		"lines": {
			"a.md": ["publish `data.batten.deny` to contribute"],
			"crates/batten/src/policy.rs": ["const DENY_RULE: &str = \"deny\";"],
		},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

test_an_unreadable_authority_a_claim_depends_on_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {"a.md": ["the guard runs on `PreToolUse` today"]},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "drift-authority-unreadable"
}

# THE SCOPE MIRROR. An authority nothing claims against is silent, which is what
# keeps this row from speaking in every fixture repository inheriting the config.
test_an_unreadable_authority_no_claim_depends_on_is_silent if {
	count({v | some v in violation; v.rule == "drift-authority-unreadable"}) == 0 with input as {"tree": {
		"lines": {"a.md": ["ordinary prose naming nothing"]},
		"documents": {},
		"missing": [],
	}}
		with data.batten.patterns as fixture_patterns
}

fixture_patterns := {
	"restated-default": "`[A-Z][A-Z0-9_]+` \\([0-9]+\\)",
	"shell-default": "\\$\\{[A-Z][A-Z0-9_]*:-[^}]*\\}",
	"policy-input-key": "`input\\.(tree|call)\\.[a-z][a-z0-9_-]*",
	"fixed-rule-ref": "`data\\.batten\\.[a-z_]+`",
	"policy-rule-const": "^const [A-Z_]+_RULE: &str = \"[a-z_]+\";",
}
