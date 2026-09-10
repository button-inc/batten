# METADATA
# description: |
#   An upper bound in the manifest and its bot-side withholding rule exist
#   together or not at all — CLOUD-593, ported from `mise-tasks/cap-drift.sh`
#   under CLOUD-843.
#
#   THE HALF-LIFT, which is the one failure mode in this area that lands GREEN.
#
#   A cap lives in two files and nothing kept them in step. The manifest carries
#   the upper bound; the bot config restates it, because the bot cannot read a
#   manifest cap and would otherwise propose a bump the manifest has already
#   refused — one unbuildable member reddening a whole grouped batch (CLOUD-344).
#
#   Lift only the manifest side and everything passes. The manifest admits the new
#   version, the bot still withholds it, nothing proposes it ever again, and no
#   check anywhere is red. The freeze survives the change that was supposed to end
#   it, and the issue closes. That is worse than the original defect, because the
#   original had a symptom.
#
#   So the predicate is SET EQUALITY, in both directions, and both directions are
#   real:
#
#     a cap with no withholding rule — the manifest refuses a version the bot will
#     propose, so the batch goes red the way CLOUD-344 measured.
#
#     a withholding rule with no cap — the bot withholds a version the manifest
#     admits, so the crate silently never advances. This is the half-lift, and it
#     is the direction with no symptom.
#
#   STILL LOAD-BEARING WITH BOTH SETS EMPTY, which is the state CLOUD-593 leaves
#   them in. It is a ratchet: the next cap added to either file has to be added to
#   the other, and this says so at the commit that adds it rather than at the
#   release that notices the freeze. A gate that only functioned while a list was
#   non-empty would have been deleted with the list.
#
#   WHAT COUNTS AS A CAP, and the narrowness is deliberate. Only an upper bound on
#   a workspace dependency — a requirement carrying a `<`. A bare caret
#   requirement bounds the MAJOR and is not an MSRV decision; treating it as one
#   would demand a withholding rule for every dependency in the file, and the gate
#   would be switched off within a day.
#
#   RULES ARE FOUND BY BRACE DEPTH, not by line shape, so a rule written inline and
#   one spread over five lines read the same — a formatter's choice must not change
#   a verdict. Names are taken from the RULE that carries the withholding key, so a
#   package matcher used for grouping, which withholds nothing, is not read as a
#   cap mirror. Comments are stripped first, because that file argues for its keys
#   at length and a gate a comment can satisfy is a gate satisfied by deleting the
#   key the comment explains.
#
#   POINTER, NEVER PAYLOAD (rule 4): the crate name and which file its counterpart
#   is missing from. Never a version range, never a manifest line.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.cap_drift

import rego.v1

rules contains "cap-drift"

manifest_path := "Cargo.toml"

bot_path := "renovate.json5"

manifest_lines := lines if {
	lines := input.tree.lines[manifest_path]
}

bot_lines := lines if {
	lines := input.tree.lines[bot_path]
}

unquoted(text) := replace(text, "\"", "")

# --- the capped set ----------------------------------------------------------
#
# Read from the workspace dependency table alone, so a `<` in a comment or in
# another table cannot mint a phantom cap.
deps_start := i if {
	some i, line in manifest_lines
	startswith(line, "[workspace.dependencies]")
}

deps_end := e if {
	after := {j |
		some j, line in manifest_lines
		j > deps_start
		startswith(line, "[")
	}
	e := min(after)
}

deps_end := count(manifest_lines) if {
	deps_start
	not another_table_follows_deps
}

another_table_follows_deps if {
	some j, line in manifest_lines
	j > deps_start
	startswith(line, "[")
}

# A requirement carrying an upper bound. The `<` is looked for inside a QUOTED
# span, so a comment beside the entry cannot supply one.
capped contains name if {
	some j, line in manifest_lines
	j > deps_start
	j < deps_end
	contains(line, "=")
	name := trim_space(substring(line, 0, indexof(line, "=")))
	name != ""
	some span in regex.find_n(data.batten.patterns["md-quoted-span"], line, -1)
	contains(span, "<")
}

# --- the withheld set --------------------------------------------------------
#
# A `//` opening a line, or following whitespace. A URL's own `//` survives.
decommented(line) := "" if {
	startswith(trim_space(line), "//")
}

decommented(line) := substring(line, 0, indexof(line, " //")) if {
	not startswith(trim_space(line), "//")
	contains(line, " //")
}

decommented(line) := line if {
	not startswith(trim_space(line), "//")
	not contains(line, " //")
}

rules_start := i if {
	some i, line in bot_lines
	contains(decommented(line), "packageRules")
	contains(decommented(line), ":")
}

# The brace delta a line contributes, and the depth the rules array is at when
# that line begins. Both are partial OBJECTS keyed by line index rather than
# functions: the depth of a line is a SUM over the lines before it, and the
# evaluator cannot schedule a function call inside the comprehension that sum
# needs. Keying them is what lets an inline rule and a five-line rule read the
# same, which is the property that keeps a formatter's choice out of the verdict.
deltas[j] := d if {
	some j, line in bot_lines
	d := count(indexof_n(decommented(line), "{")) - count(indexof_n(decommented(line), "}"))
}

depth[j] := total if {
	some j, _ in bot_lines
	j >= rules_start
	total := sum([deltas[k] |
		some k, _ in bot_lines
		k >= rules_start
		k < j
	])
}

# A rule opens on a line that is at depth zero and carries a brace.
rule_open contains j if {
	some j, line in bot_lines
	depth[j] == 0
	contains(decommented(line), "{")
}

# and closes on the first line at or after it where the depth returns to zero.
rule_close(j) := e if {
	closers := {k |
		some k, _ in bot_lines
		k >= j
		depth[k] + deltas[k] == 0
	}
	e := min(closers)
}

rule_text(j) := concat("\n", [decommented(bot_lines[k]) |
	some k, _ in bot_lines
	k >= j
	k <= rule_close(j)
])

# Every name in a rule that carries the withholding key. Scoped to the RULE, so a
# package matcher used for grouping is not read as a cap mirror.
withheld contains name if {
	some j in rule_open
	text := rule_text(j)
	contains(text, "allowedVersions")
	contains(text, "matchPackageNames")
	after := substring(text, indexof(text, "matchPackageNames"), -1)
	list := substring(after, indexof(after, "[") + 1, (indexof(after, "]") - indexof(after, "[")) - 1)
	some raw in split(list, ",")
	name := trim_space(replace(replace(raw, "\"", ""), "'", ""))
	name != ""
}

# --- the two directions ------------------------------------------------------

violation contains {
	"rule": "cap-drift",
	"verdict": "bound carry missing",
	"subjects": [{"artifact": sprintf("%s absent from %s", [name, bot_path])}],
} if {
	bot_lines
	some name in capped
	not name in withheld
}

# THE HALF-LIFT, and the direction with no symptom.
violation contains {
	"rule": "cap-drift",
	"verdict": "bound carry missing",
	"subjects": [{"artifact": sprintf("%s absent from %s", [name, manifest_path])}],
} if {
	manifest_lines
	some name in withheld
	not name in capped
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves both files
# into one map in a single evaluation — a `with input as` block fabricates exactly
# that map (CLOUD-845), and this rule's whole subject is the pairing across the
# two. `crates/batten/tests/it/cap_drift.rs` is that tier.

tree(manifest, bot) := {"tree": {"lines": {"Cargo.toml": manifest, "renovate.json5": bot}}}

deps(entries) := array.concat(array.concat(["[workspace.dependencies]"], entries), ["[workspace.lints]"])

bot_config(rules_text) := array.concat(
	array.concat(["{", "  \"$schema\": \"https://docs.renovatebot.com/renovate-schema.json\",", "  packageRules: ["], rules_text),
	["  ],", "}"],
)

test_both_sets_empty_is_clean if {
	count(violation) == 0 with input as tree(deps(["serde = \"1\""]), bot_config([]))
}

test_a_cap_with_its_withholding_rule_is_clean if {
	count(violation) == 0 with input as tree(
		deps(["ignore = \">=0.4, <0.4.30\""]),
		bot_config(["    { matchPackageNames: [\"ignore\"], allowedVersions: \"<0.4.30\" },"]),
	)
}

test_a_cap_with_no_withholding_rule_is_refused if {
	some v in violation with input as tree(deps(["ignore = \">=0.4, <0.4.30\""]), bot_config([]))
	v.verdict == "bound carry missing"
}

# THE HALF-LIFT: the manifest side lifted, the bot side left withholding.
test_a_withholding_rule_with_no_cap_is_refused if {
	some v in violation with input as tree(
		deps(["ignore = \"0.4\""]),
		bot_config(["    { matchPackageNames: [\"ignore\"], allowedVersions: \"<0.4.30\" },"]),
	)
	v.verdict == "bound carry missing"
}

# A bare caret requirement bounds the MAJOR and is not a cap.
test_a_caret_requirement_is_not_a_cap if {
	count(violation) == 0 with input as tree(deps(["serde = \"1.0\""]), bot_config([]))
}

# A formatter's choice must not change a verdict: a rule spread over lines reads
# the same as one written inline.
test_a_multiline_rule_reads_the_same_as_an_inline_one if {
	count(violation) == 0 with input as tree(
		deps(["ignore = \">=0.4, <0.4.30\""]),
		bot_config([
			"    {",
			"      matchPackageNames: [\"ignore\"],",
			"      allowedVersions: \"<0.4.30\",",
			"    },",
		]),
	)
}

# A matcher used for GROUPING withholds nothing and must not read as a mirror.
test_a_grouping_matcher_is_not_a_cap_mirror if {
	some v in violation with input as tree(
		deps(["ignore = \">=0.4, <0.4.30\""]),
		bot_config(["    { matchPackageNames: [\"ignore\"], groupName: \"rust\" },"]),
	)
	v.verdict == "bound carry missing"
}

# A gate a COMMENT can satisfy is a gate satisfied by deleting the key the
# comment explains.
test_a_commented_rule_does_not_satisfy_the_pairing if {
	some v in violation with input as tree(
		deps(["ignore = \">=0.4, <0.4.30\""]),
		bot_config(["    // { matchPackageNames: [\"ignore\"], allowedVersions: \"<0.4.30\" },"]),
	)
	v.verdict == "bound carry missing"
}

# A `<` in a comment beside an entry cannot mint a phantom cap.
test_a_less_than_in_a_comment_is_not_a_cap if {
	count(violation) == 0 with input as tree(
		deps(["serde = \"1.0\" # was <2 before the bump"]),
		bot_config([]),
	)
}

#MUTANT-SUITE crates/batten/tests/it/cap_drift.rs
#MUTANT only-checks-cap-without-rule|s@^\tsome name in withheld$@\tsome name in capped@|the_half_lift_is_refused
#MUTANT grouping-matcher-read-as-a-mirror|s@^\tcontains(text, "allowedVersions")$@\ttrue@|a_grouping_matcher_is_not_a_cap_mirror
