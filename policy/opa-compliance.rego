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

# METADATA
# description: |
#   Bound to the tree surface. This block has PACKAGE scope and is the one binding
#   for `package batten`, so it covers `policy/privileged-lane.rego` too -- OPA
#   refuses a redeclaration, and that module points here rather than repeating it.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form `schema.policy-input.schema` is a parse error reported as
#   `invalid schema reference` rather than as a missing bind.
#   Without a block like this the module is silently UNCHECKED -- measured, a rule
#   reading `input.tree.trackd` with no annotation passes `opa check -s` at exit 0,
#   which is the hole CLOUD-876 exists to close.
# schemas:
#   - input: schema["policy-input.schema"]

package batten

import rego.v1

# A gate outside $MUTANT_GATES with no row here fails `mise run mutant-census`.
#MUTANT-EXEMPT CLOUD-845|no compiled-binary tier names this module at all, so there is no suite a declared mutation could redden. That is not the `tests/$gate.bats` hole CLOUD-1267 closed — a suite may now be DECLARED — it is that none exists to declare, and what is owed is the tier

rules contains "opa-tracks-regorus-compliance"

# A file this build could not parse lands in `input.tree.missing` rather than in
# `documents` (CLOUD-845). Without this clause an unparseable manifest is simply
# absent from every rule below and the module reports GREEN over a file it never
# read — a vacuous pass, indistinguishable from a real one.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "source parse broken",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	judged(path)
}

# The checker and the evaluator naming different OPA release lines.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "version pin ahead",
	"subjects": [{"artifact": pin}, {"artifact": declared}],
} if {
	pin := opa_pin
	declared := declared_level
	version_line(pin) != version_line(declared)
}

# The recorded compliance claim was read against a different regorus than the one
# this commit resolves. The number may still be right; nothing here has checked,
# and that is the point.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "claim state stale",
	"subjects": [{"artifact": recorded_for}, {"artifact": regorus_pin}],
} if {
	recorded_for := compliance_for
	version_line(recorded_for) != version_line(regorus_pin)
}

judged(path) if path == "mise.toml"

judged(path) if path == "Cargo.toml"

# --- absent and malformed are findings, not silence -------------------------
#
# THE VACUOUS PASS THIS CLOSES, and it was shipped in the first version of this
# module. `input.tree.missing` catches a file that failed to PARSE. It says
# nothing about a file that parses cleanly and simply LACKS the key — and in
# Rego an undefined reference makes its whole rule body undefined, so every
# comparison below silently produced no result. Measured on the first version
# with all four keys deleted: `opa eval` returned `[]`. Delete the `opa` pin and
# the gate reported green over a manifest it had never read.
#
# That is CLOUD-845's class exactly, in the module whose own header cites it,
# which is the point worth keeping: the three-valued discipline has to be
# written per ACCESSOR, not once per file. The bash draft this replaced got it
# right by accident, because a shell variable that comes back empty is visible
# where an undefined Rego reference is not.
#
# Reported per key rather than as one "could not read the manifest": a reader
# fixing a deleted pin must not also be told the compliance level is missing
# when it is sitting right there.

required contains {"key": "the `opa` pin", "owner": "mise.toml", "value": opa_pin} if opa_pin

required contains {"key": "`REGORUS_OPA_COMPLIANCE`", "owner": "mise.toml", "value": declared_level} if declared_level

required contains {"key": "`REGORUS_OPA_COMPLIANCE_FOR`", "owner": "mise.toml", "value": compliance_for} if compliance_for

required contains {"key": "the `regorus` pin", "owner": "Cargo.toml", "value": regorus_pin} if regorus_pin

# APPLICABILITY, AND IT IS NOT A DODGE. The question this rule asks is "does the
# pinned checker track the regorus this workspace resolves". A tree that carries
# no `Cargo.toml` is not that workspace and has no such claim to check — the
# absent keys there are not a finding, they are the rule not applying.
#
# THIS WAS FOUND BY BREAKING IT. Shipped without the guard, the absent-key
# clauses fired three times inside `tests/prebuilt-lint.bats`'s fixtures, which
# write a minimal `mise.toml` and no `Cargo.toml`: every fixture case expecting
# exit 0 went red while the real tree stayed green. That is CLOUD-614's lesson
# arriving from the other side — `claim-not-raced` keeps itself out of fixtures
# with a glob naming its own file, and a `sources`-driven row needs the same
# discipline expressed as an applicability conjunct.
#
# The residual hole is named rather than left implicit: deleting `Cargo.toml`
# outright silences this rule. That is not a gap worth a clause, because a Rust
# workspace without a manifest does not build, and a gate is not the thing that
# should notice.
in_this_workspace if input.tree.documents["Cargo.toml"]

# One clause per accessor, each guarded on its OWNING document being present —
# an absent document is already reported above, and reporting it twice would
# name the caller's parse failure as four separate findings.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "claim declare absent",
	"subjects": [{"artifact": "opa"}],
} if {
	in_this_workspace
	input.tree.documents["mise.toml"]
	not opa_pin
}

violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "claim declare absent",
	"subjects": [{"artifact": "REGORUS_OPA_COMPLIANCE"}],
} if {
	in_this_workspace
	input.tree.documents["mise.toml"]
	not declared_level
}

violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "claim declare absent",
	"subjects": [{"artifact": "REGORUS_OPA_COMPLIANCE_FOR"}],
} if {
	in_this_workspace
	input.tree.documents["mise.toml"]
	not compliance_for
}

violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "claim declare absent",
	"subjects": [{"artifact": "regorus"}],
} if {
	in_this_workspace
	not regorus_pin
}

# A value that is present but is not a version. `version_line` is undefined for
# a non-string and for a single-component string, and without this clause that
# undefined propagates into the comparisons as silence — the same vacuous pass
# one level in. `"1"` against a declared `1.2.0` was measured passing.
violation contains {
	"rule": "opa-tracks-regorus-compliance",
	"verdict": "version read unread",
	"subjects": [{"artifact": entry.key}, {"artifact": entry.owner}],
} if {
	in_this_workspace
	some entry in required
	not version_line(entry.value)
}

opa_pin := input.tree.documents["mise.toml"].tools["aqua:open-policy-agent/opa"]

declared_level := input.tree.documents["mise.toml"].env.REGORUS_OPA_COMPLIANCE

compliance_for := input.tree.documents["mise.toml"].env.REGORUS_OPA_COMPLIANCE_FOR

# BOTH SPELLINGS, for `msrv-pin-agreement`'s stated reason: the inline-table form
# is what this manifest uses, and a bare `regorus = "0.11"` is legal TOML that a
# gate understanding only one spelling would report as an absent pin. The two
# definitions are mutually exclusive — `.version` on a string is undefined — so
# they cannot conflict.
regorus_pin := input.tree.documents["Cargo.toml"].workspace.dependencies.regorus.version

regorus_pin := v if {
	v := input.tree.documents["Cargo.toml"].workspace.dependencies.regorus
	is_string(v)
}

# MAJOR.MINOR, AND ONLY THAT — `msrv-pin-agreement`'s rule, for its reason. A
# patch component says nothing about the language line, so comparing raw strings
# would redden on every patch bump of either side, which is the false-positive
# rate that gets a gate switched off. `0.11` and `1.2.0` both reduce cleanly.
#
# Undefined for a non-string and for a single-component string, which is what
# the malformed clause above reads — the narrowing lives here so there is one
# definition of "is a version" rather than one per caller.
version_line(v) := concat(".", [parts[0], parts[1]]) if {
	is_string(v)
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
	"missing": {},
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
		"missing": {"mise.toml": "absent"},
	}}
}

test_an_unparseable_cargo_manifest_denies_rather_than_passing if {
	count(violation) == 1 with input as {"tree": {
		"documents": {},
		"missing": {"Cargo.toml": "absent"},
	}}
}

# `missing` carrying something this rule does not judge is not its finding.
test_a_missing_unrelated_file_is_not_this_rules_finding if {
	count(violation) == 0 with input as {"tree": {
		"documents": {},
		"missing": {"README.md": "absent"},
	}}
}

# --- absent and malformed values --------------------------------------------
#
# THE FIRST VERSION OF THIS MODULE PASSED EVERY ONE OF THESE. Measured with
# `opa eval` over a manifest that parses and carries none of the four keys:
# `[]`. These are the rows that make the module's own could-not-look claim true
# rather than decorative.

# A manifest that parses and carries nothing is FOUR findings, not silence and
# not one — each key is separately unreadable and separately fixable.
test_a_manifest_with_no_values_is_four_findings_not_silence if {
	count(violation) == 4 with input as {"tree": {
		"documents": {
			"mise.toml": {"tools": {}, "env": {}},
			"Cargo.toml": {"workspace": {"dependencies": {"regorus": {}}}},
		},
		"missing": {},
	}}
}

test_a_deleted_opa_pin_is_a_finding if {
	count(violation) == 1 with input as {"tree": {
		"documents": {
			"mise.toml": {"tools": {}, "env": {
				"REGORUS_OPA_COMPLIANCE": "1.2.0",
				"REGORUS_OPA_COMPLIANCE_FOR": "0.11",
			}},
			"Cargo.toml": {"workspace": {"dependencies": {"regorus": {"version": "0.11"}}}},
		},
		"missing": {},
	}}
}

test_a_deleted_compliance_level_is_a_finding if {
	count(violation) == 1 with input as {"tree": {
		"documents": {
			"mise.toml": {
				"tools": {"aqua:open-policy-agent/opa": "1.2.0"},
				"env": {"REGORUS_OPA_COMPLIANCE_FOR": "0.11"},
			},
			"Cargo.toml": {"workspace": {"dependencies": {"regorus": {"version": "0.11"}}}},
		},
		"missing": {},
	}}
}

test_a_deleted_compliance_target_is_a_finding if {
	count(violation) == 1 with input as {"tree": {
		"documents": {
			"mise.toml": {
				"tools": {"aqua:open-policy-agent/opa": "1.2.0"},
				"env": {"REGORUS_OPA_COMPLIANCE": "1.2.0"},
			},
			"Cargo.toml": {"workspace": {"dependencies": {"regorus": {"version": "0.11"}}}},
		},
		"missing": {},
	}}
}

test_a_deleted_regorus_pin_is_a_finding if {
	count(violation) == 1 with input as {"tree": {
		"documents": {
			"mise.toml": {
				"tools": {"aqua:open-policy-agent/opa": "1.2.0"},
				"env": {
					"REGORUS_OPA_COMPLIANCE": "1.2.0",
					"REGORUS_OPA_COMPLIANCE_FOR": "0.11",
				},
			},
			"Cargo.toml": {"workspace": {"dependencies": {}}},
		},
		"missing": {},
	}}
}

# A single-component version. `version_line` is undefined for it, and the first
# version let that undefined pass as agreement — measured: `"1"` against a
# declared `1.2.0` produced no finding.
test_a_single_component_version_is_a_finding if {
	count(violation) == 1 with input as tree("1", "1.2.0", "0.11", "0.11")
}

# A non-string where a version belongs. `split` on a number is undefined, which
# is the same silence by a different route.
test_a_non_string_version_is_a_finding if {
	count(violation) == 1 with input as tree(120, "1.2.0", "0.11", "0.11")
}

# The bare-string dependency spelling is legal TOML, and a gate understanding
# only the inline table would report a present pin as absent —
# `msrv-pin-agreement` handles both spellings for this reason.
# THE CASE THAT WOULD HAVE CAUGHT THE REGRESSION. A tree carrying a `mise.toml`
# and no `Cargo.toml` is not this workspace: the pins are absent because the
# question does not apply, not because somebody deleted them. Shipped without
# this, the absent-key clauses fired three times in every `prebuilt-lint.bats`
# fixture and reddened each case that expected exit 0, while the real tree
# stayed green — so the suite that caught it was not this one, and that is
# exactly why the case belongs here now.
test_a_tree_that_is_not_this_workspace_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"documents": {"mise.toml": {"tools": {}, "env": {}}},
		"missing": {},
	}}
}

test_a_bare_string_regorus_pin_is_read_not_reported_absent if {
	count(violation) == 0 with input as {"tree": {
		"documents": {
			"mise.toml": {
				"tools": {"aqua:open-policy-agent/opa": "1.2.0"},
				"env": {
					"REGORUS_OPA_COMPLIANCE": "1.2.0",
					"REGORUS_OPA_COMPLIANCE_FOR": "0.11",
				},
			},
			"Cargo.toml": {"workspace": {"dependencies": {"regorus": "0.11"}}},
		},
		"missing": {},
	}}
}
