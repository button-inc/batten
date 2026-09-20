# METADATA
# description: |
#   The review bot's config still carries the keys the review lifecycle depends
#   on — CLOUD-860, the missing half of CLOUD-847, ported from
#   `mise-tasks/coderabbit-config-check.sh` under CLOUD-843.
#
#   CLOUD-847 landed the config and measured every key in it; nothing then held
#   the file to those readings, so a rule shipped without a mechanism — the shape
#   non-negotiable rule 2 names.
#
#   THE THREE KEYS ARE NOT A STYLE PREFERENCE, they are what the lifecycle rests
#   on:
#
#     the changes-requested workflow — findings arrive as a FORMAL review, so the
#     forge's review decision carries an answer. Off, the bot only comments and the
#     decision stays null, which the gates downstream read as no review at all.
#
#     review of drafts — the draft phase is the free phase, since every CI job here
#     is conditioned on the pull request not being a draft. Off, nothing reviews it
#     and the review can only arrive after the ready, which is the whole defect
#     CLOUD-847 measured.
#
#     the secret scanner — the ONLY secret scanning a draft gets, for the same
#     reason. The other linters are deliberately off because this repository's own
#     gates already run them; this one is deliberately kept.
#
#   WHY THE FAILURE IS WORTH A GATE RATHER THAN A COMMENT. Flipping the draft key
#   back is a one-line diff, and its symptom is SILENCE: reviews stop happening,
#   which looks exactly like nobody having pushed. The gate that consumes the
#   config would then refuse every pull request for want of a review the config
#   quietly stopped producing, and the visible failure would be the gate rather
#   than the cause.
#
#   ABSENT IS NOT PASSING for the first two, and that asymmetry is the point: a key
#   nobody wrote and a key someone deleted are the same file, and both leave the
#   DEFAULT in force — which is the value this exists to refuse. The scanner is the
#   inverse, because its default is already enabled: only an explicit denial is a
#   violation there, so absence passes.
#
#   THE SCANNER'S KEY IS SCOPED TO ITS OWN BLOCK. The enabling key appears once per
#   tool, so reading it unscoped would answer about whichever tool happened to come
#   first in the file.
#
#   A FILE WITH NO KEYS AT ALL IS THE VACUOUS PASS this is shaped to avoid: every
#   assertion here is ABOUT a key, so a file carrying none of them satisfies all of
#   them by having nothing to judge.
#
#   POINTER, NEVER PAYLOAD (rule 4): a path, a line and the key, never a byte of
#   the file. A config can carry review instructions and paths, and a gate that
#   echoed them would put them in every CI log.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.coderabbit_config

import rego.v1

rules contains "review declare wrong"

config_path := ".coderabbit.yaml"

config_lines := lines if {
	lines := input.tree.lines[config_path]
}

# The keys whose DEFAULT is the value this refuses, so absence is a violation.
required_true := {"request_changes_workflow", "drafts"}

# The tool whose default is already enabled, so only an explicit denial is one.
scanner := "gitleaks"

commented(line) if {
	startswith(trim_space(line), "#")
}

# A key line at any indentation, with its own value. The file is this
# repository's and its shape is reviewed, so this reads the KEY rather than
# building a document tree.
# **EVERY MATCH, AS A SET** (CLOUD-1880, PR #928). `key_at` was a complete
# function, and a YAML file may carry the same key twice — two uncommented
# `enabled:` lines under different blocks is the ordinary way it happens. Each
# match builds a DIFFERENT object, because `line` differs, so regorus raises
# `eval_conflict_error` AT EVALUATION the moment a violation rule reads
# `key_at(...)`; `policy_rule` discards the whole document on a fault, so this
# module stops deciding and exits 0 over a config it never judged. That is
# CLOUD-1049's fault class.
key_matches(name) := [{"line": i + 1, "value": value} |
	some i, line in config_lines
	not commented(line)
	contains(line, ":")
	trim_space(substring(line, 0, indexof(line, ":"))) == name
	value := value_of(line)
]

# THE LAST ONE WINS, because that is what the reader this gate is about does:
# YAML resolves a duplicate key to its final binding, so judging an earlier one
# would be a verdict about a value nothing uses. Undefined when there is no
# match, which is the absence every caller below already handles.
key_at(name) := match if {
	found := key_matches(name)
	count(found) > 0
	match := found[count(found) - 1]
}

# AND THE DUPLICATE IS ITSELF REPORTED, rather than silently resolved. Two
# bindings for a key this gate decides on means the file says two things, and a
# reader who changes the first one would see no effect — the shape that wastes an
# afternoon. Naming it is cheap; resolving it quietly is how the ambiguity
# survives.
violation contains {
	"rule": "review declare wrong",
	"verdict": "config carry empty",
	"subjects": [{"path": config_path}, {"artifact": name}],
} if {
	some name in required_true
	count(key_matches(name)) > 1
}

value_of(line) := trim_space(substring(after, 0, indexof(after, "#"))) if {
	after := substring(line, indexof(line, ":") + 1, -1)
	contains(after, "#")
}

value_of(line) := trim_space(substring(line, indexof(line, ":") + 1, -1)) if {
	not contains(substring(line, indexof(line, ":") + 1, -1), "#")
}

any_key_declared if {
	some line in config_lines
	not commented(line)
	contains(line, ":")
	trim_space(substring(line, 0, indexof(line, ":"))) != ""
}

# --- the vacuity guard, and it is first --------------------------------------
violation contains {
	"rule": "review declare wrong",
	"verdict": "config carry empty",
	"subjects": [{"path": config_path}],
} if {
	config_lines
	not any_key_declared
}

# --- the two keys whose absence leaves the default in force ------------------
violation contains {
	"rule": "review declare wrong",
	"verdict": "config carry empty",
	"subjects": [{"artifact": sprintf("%s absent", [name])}],
} if {
	any_key_declared
	some name in required_true
	not key_at(name)
}

violation contains {
	"rule": "review declare wrong",
	"verdict": "config state wrong",
	"subjects": [{"path": sprintf("%s:%d", [config_path, key_at(name).line])}],
} if {
	some name in required_true
	key_at(name).value != "true"
}

# --- the scanner, whose default is the compliant one -------------------------
#
# Scoped to its own block: the enabling key appears once per tool, so an unscoped
# read answers about whichever tool came first.
scanner_start := i if {
	some i, line in config_lines
	not commented(line)
	trim_space(line) == concat("", [scanner, ":"])
}

# The block ends at the next key at the scanner's own indentation or shallower.
scanner_end := e if {
	after := {j |
		some j, line in config_lines
		j > scanner_start
		not commented(line)
		trim_space(line) != ""
		indent(line) <= indent(config_lines[scanner_start])
	}
	e := min(after)
}

scanner_end := count(config_lines) if {
	scanner_start
	not another_key_after_scanner
}

another_key_after_scanner if {
	some j, line in config_lines
	j > scanner_start
	not commented(line)
	trim_space(line) != ""
	indent(line) <= indent(config_lines[scanner_start])
}

# The column the line's content starts at, which is what separates a key inside
# the scanner's block from the next key beside it.
indent(line) := indexof(line, trim_space(line))

scanner_enabled := {"line": j + 1, "value": value_of(config_lines[j])} if {
	some j, line in config_lines
	j > scanner_start
	j < scanner_end
	not commented(line)
	trim_space(substring(line, 0, indexof(line, ":"))) == "enabled"
	contains(line, ":")
}

violation contains {
	"rule": "review declare wrong",
	"verdict": "config state wrong",
	"subjects": [{"path": sprintf("%s:%d", [config_path, scanner_enabled.line])}],
} if {
	scanner_enabled.value == "false"
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves the declared
# `line_sources` path to the committed bytes at all (CLOUD-845), which for this
# rule is the whole no-fail-open claim: the input is a tracked file in this
# checkout, so "could not look" means the file is gone, which is itself the
# violation this refuses. `crates/batten/tests/it/coderabbit_config.rs` is that
# tier.

cfg(lines) := {"tree": {"lines": {".coderabbit.yaml": lines}}}

healthy := [
	"reviews:",
	"  request_changes_workflow: true",
	"  auto_review:",
	"    drafts: true",
	"  tools:",
	"    gitleaks:",
	"      enabled: true",
	"    ruff:",
	"      enabled: false",
]

test_the_three_keys_holding_is_clean if {
	count(violation) == 0 with input as cfg(healthy)
}

# THE SHAPE THAT USED TO KILL THE MODULE (CLOUD-1880). A duplicate uncommented
# key built two DIFFERENT objects, because `line` differs, so `key_at` raised
# `eval_conflict_error` the moment a violation rule read it — and a faulting
# module returns no violations at all, which is byte-identical to a clean file on
# the decision surface.
#
# The assertion is that a verdict comes back, not that the file is clean: a case
# asserting `count(violation) == 0` would have passed on the corpse.
test_a_duplicate_key_still_yields_a_verdict if {
	some v in violation with input as cfg(array.concat(healthy, ["  request_changes_workflow: true"]))
	v.verdict == "config carry empty"
}

# THE LAST BINDING DECIDES, because that is what the YAML reader this gate is
# about does. A file whose final `request_changes_workflow` is false is refused
# even though an earlier one says true — judging the earlier one would be a
# verdict about a value nothing uses.
test_the_last_binding_is_the_one_judged if {
	some v in violation with input as cfg(array.concat(healthy, ["  request_changes_workflow: false"]))
	v.verdict == "config state wrong"
}

test_the_changes_workflow_flipped_off_is_refused if {
	some v in violation with input as cfg(["reviews:", "  request_changes_workflow: false", "    drafts: true"])
	v.verdict == "config state wrong"
}

# ABSENT IS NOT PASSING: a key nobody wrote and a key someone deleted are the
# same file, and both leave the default in force.
test_an_absent_required_key_is_refused if {
	some v in violation with input as cfg(["reviews:", "  request_changes_workflow: true"])
	v.verdict == "config carry empty"
}

test_the_draft_key_flipped_off_is_refused if {
	some v in violation with input as cfg([
		"reviews:",
		"  request_changes_workflow: true",
		"  auto_review:",
		"    drafts: false",
	])
	v.verdict == "config state wrong"
}

# The scanner's default is already enabled, so absence is compliant.
test_an_absent_scanner_block_passes if {
	count(violation) == 0 with input as cfg([
		"reviews:",
		"  request_changes_workflow: true",
		"  auto_review:",
		"    drafts: true",
	])
}

test_the_scanner_denied_explicitly_is_refused if {
	some v in violation with input as cfg(array.concat(
		["reviews:", "  request_changes_workflow: true", "  auto_review:", "    drafts: true", "  tools:", "    gitleaks:"],
		["      enabled: false"],
	))
	v.verdict == "config state wrong"
}

# The enabling key appears once per tool: an unscoped read would answer about
# whichever tool came first.
test_another_tools_denial_does_not_answer_for_the_scanner if {
	count(violation) == 0 with input as cfg([
		"reviews:",
		"  request_changes_workflow: true",
		"  auto_review:",
		"    drafts: true",
		"  tools:",
		"    ruff:",
		"      enabled: false",
		"    gitleaks:",
		"      enabled: true",
	])
}

# THE VACUOUS PASS this is shaped to avoid.
test_a_comment_only_file_is_a_failure_not_a_vacuous_pass if {
	some v in violation with input as cfg(["# every key was removed", "# and this still parses"])
	v.verdict == "config carry empty"
}

# A commented key is not a declared one.
test_a_commented_key_does_not_answer_for_the_real_one if {
	some v in violation with input as cfg([
		"reviews:",
		"  # request_changes_workflow: true",
		"  auto_review:",
		"    drafts: true",
	])
	v.verdict == "config carry empty"
}

#MUTANT-SUITE crates/batten/tests/it/coderabbit_config.rs
#MUTANT flipped-key-passes|s@^\tkey_at(name).value != "true"$@\tfalse@|the_changes_workflow_flipped_off_is_refused
#MUTANT absent-key-passes|s@^\tnot key_at(name)$@\tfalse@|an_absent_required_key_is_refused
#MUTANT empty-file-is-a-pass|s@^\tnot any_key_declared$@\tfalse@|a_comment_only_file_is_a_failure_not_a_vacuous_pass
