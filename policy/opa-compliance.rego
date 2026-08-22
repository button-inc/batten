# The pinned Rego type checker must track the shipped Rego evaluator (CLOUD-876).
#
# WHY TWO IMPLEMENTATIONS EXIST AT ALL, since that is what makes skew possible.
# CLOUD-876 decided the schema mechanism, and regorus lost: it has no static
# undefined-field checker, and its `Target`/`Schema` surface is unreachable here
# anyway — that surface sits behind upstream's `azure_policy` feature, which
# drags in `jsonschema` (refused by `evaluator-closure-check`) and
# `core-foundation-sys` via chrono (refused by `macos-link-check`). So the corpus
# is TYPE CHECKED by upstream `opa` at build time and EVALUATED by regorus at
# runtime. A rule that type checks under one and evaluates under the other is a
# false green, and the type check is the half nobody re-runs.
#
# WHY THIS IS A POLICY ROW AND NOT A BASH GATE. It was written as bash first, and
# that was the campaign's own defect reappearing inside the bundle meant to end it
# (CLOUD-843: "measured, the bash grew today"). Everything it decides lives in two
# tracked TOML files, which is exactly CLOUD-846's structured-config bucket — the
# gates measured as migratable today. `policy/privileged-lane.rego` is the shape.
#
# WHAT IT DELIBERATELY DOES NOT DO. The bash draft derived the compliance level by
# reading the vendored crate's README, and argued that was better than restating
# the number. It is not: "what does upstream claim right now" is a property of the
# WORLD, and `lock-complete`'s split puts that on a clock, never in a gate — a
# gate answering it fails a branch for drift it did not cause, and needs a spawn
# and an out-of-tree path to do it. What IS a property of the commit is whether
# the numbers this commit pins agree, and that is all this decides.
#
# THE THIRD CONJUNCT IS WHAT STOPS THE RECORDED LEVEL ROTTING. A declared level
# alone would be a constant nobody re-reads. `REGORUS_OPA_COMPLIANCE_FOR` records
# the regorus line the claim was read against, and a regorus bump that leaves it
# behind is a finding — so the human is sent back to upstream's README exactly
# when upstream is the thing that moved, and never otherwise.

package batten

import rego.v1

rules contains "opa-tracks-regorus-compliance"

# A file this build could not parse lands in `input.tree.missing` rather than in
# `documents` (CLOUD-845). Without this clause an unparseable manifest is simply
# absent from every rule below and the module reports GREEN over a file it never
# read — a vacuous pass, indistinguishable from a real one.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"msg": sprintf("%s could not be parsed, so the pinned checker was never judged against the shipped evaluator", [path]),
} if {
	some path in input.tree.missing
	judged(path)
}

# The checker and the evaluator naming different OPA release lines.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"msg": sprintf(
		"mise.toml pins opa %s but records regorus as compliant with OPA v%s — a rule type checked by one and evaluated by the other is a false green",
		[pin, declared],
	),
} if {
	pin := opa_pin
	declared := declared_level
	line(pin) != line(declared)
}

# The recorded compliance claim was read against a different regorus than the one
# this commit resolves. The number may still be right; nothing here has checked,
# and that is the point.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"msg": sprintf(
		"the recorded OPA compliance level was read against regorus %s but Cargo.toml pins %s — re-read upstream's declared level and move both, or the pin tracks a claim nobody has checked",
		[recorded_for, regorus_pin],
	),
} if {
	recorded_for := compliance_for
	line(recorded_for) != line(regorus_pin)
}

judged(path) if path == "mise.toml"

judged(path) if path == "Cargo.toml"

opa_pin := input.tree.documents["mise.toml"].tools["aqua:open-policy-agent/opa"]

declared_level := input.tree.documents["mise.toml"].env.REGORUS_OPA_COMPLIANCE

compliance_for := input.tree.documents["mise.toml"].env.REGORUS_OPA_COMPLIANCE_FOR

regorus_pin := input.tree.documents["Cargo.toml"].workspace.dependencies.regorus.version

# MAJOR.MINOR, AND ONLY THAT — `msrv-pin-agreement`'s rule, for its reason. A
# patch component says nothing about the language line, so comparing raw strings
# would redden on every patch bump of either side, which is the false-positive
# rate that gets a gate switched off. `0.11` and `1.2.0` both reduce cleanly.
line(v) := concat(".", [parts[0], parts[1]]) if {
	parts := split(v, ".")
	count(parts) >= 2
}

# --- tests -----------------------------------------------------------------
#
# `with input as` throughout: these assert the PREDICATE. A suite reading the real
# tree would go quiet the moment the tree was correct and pass forever after,
# including through a regression.

tree(opa, declared, for_regorus, regorus) := {"tree": {
	"documents": {
		"mise.toml": {
			"tools": {"aqua:open-policy-agent/opa": opa},
			"env": {
				"REGORUS_OPA_COMPLIANCE": declared,
				"REGORUS_OPA_COMPLIANCE_FOR": for_regorus,
			},
		},
		"Cargo.toml": {"workspace": {"dependencies": {"regorus": {"version": regorus}}}},
	},
	"missing": [],
}}

test_agreeing_pins_pass if {
	count(violation) == 0 with input as tree("1.2.0", "1.2.0", "0.11", "0.11")
}

# The live hazard: `opa` bumped to a current release while regorus still tracks
# 1.2.0. Both are 1.x, so a major-only comparison would miss it.
test_a_checker_ahead_of_the_evaluator_denies if {
	count(violation) == 1 with input as tree("1.9.0", "1.2.0", "0.11", "0.11")
}

# A checker BEHIND the declared level is refused too: this is an equality, not a
# bound. An older checker type checks against a language the shipped engine has
# already moved past.
test_a_checker_behind_the_evaluator_denies if {
	count(violation) == 1 with input as tree("1.0.0", "1.2.0", "0.11", "0.11")
}

test_a_patch_only_difference_is_agreement if {
	count(violation) == 0 with input as tree("1.2.1", "1.2.0", "0.11", "0.11")
}

# THE CLAUSE THAT STOPS THE RECORDED LEVEL ROTTING. regorus moved; the recorded
# claim did not. The compliance number may still be correct — nothing has looked,
# which is exactly what this reports.
test_a_regorus_bump_past_the_recorded_claim_denies if {
	count(violation) == 1 with input as tree("1.2.0", "1.2.0", "0.11", "0.12")
}

# Both halves wrong is two findings, not one — a reader fixing the pin must not be
# told the claim is now current.
test_both_disagreements_are_reported_separately if {
	count(violation) == 2 with input as tree("1.9.0", "1.2.0", "0.11", "0.12")
}

test_an_unparseable_manifest_denies_rather_than_passing if {
	count(violation) == 1 with input as {"tree": {
		"documents": {},
		"missing": ["mise.toml"],
	}}
}

test_an_unparseable_cargo_manifest_denies_rather_than_passing if {
	count(violation) == 1 with input as {"tree": {
		"documents": {},
		"missing": ["Cargo.toml"],
	}}
}

# `missing` carrying something this rule does not judge is not its finding.
test_a_missing_unrelated_file_is_not_this_rules_finding if {
	count(violation) == 0 with input as {"tree": {
		"documents": {},
		"missing": ["README.md"],
	}}
}
