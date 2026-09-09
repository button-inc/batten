# METADATA
# description: |
#   The hook step's trigger covers every path the config makes an input — CLOUD-224,
#   ported from `mise-tasks/batten-glob-check.sh` under CLOUD-843.
#
#   The `batten-check` step used to carry no glob at all, so `batten check` ran on
#   every commit whatever it touched. Giving it a glob is what makes a docs-only
#   commit cheap; the cost is that the step's trigger becomes a SECOND authority
#   over a set the config already defines, and a second authority narrows silently.
#
#   The failure that produces is the one the gate model exists to prevent: add a
#   `[[rule]]` whose glob names a path outside the step's list, and the gate simply
#   stops running for commits that touch only that path. Nothing goes red. The
#   whole-tree run in CI still covers it, so the symptom is a rule that quietly does
#   not gate a branch — feedback deleted, verdict preserved.
#
#   WHAT `check` READS out of the config is three things: every `[[rule]]`'s own
#   `glob`; the instruction budget's `files` array and every embedded `path`,
#   because a declared budget is a gate under `check` and not only under its own
#   verb; and a defects ledger path, which this consumer declares nowhere today and
#   is the case to extend here when it does.
#
#   NOT CHECKED, and not checkable by a glob at all: a `ratchet` rule's verdict also
#   moves when its base moves, with no file in this repository changing. That is a
#   property of the world, and the whole-tree run in CI is what covers it.
#
#   THE PREDICATE IS THIS CONSUMER'S, NOT THE ENGINE'S. That this repository drives
#   its gate from a hook manifest, and which step inside it carries the trigger, are
#   facts about this consumer — non-negotiable rule 1 — so the containment lives in
#   a `policy/*.rego` module and not in engine source.
#
#   THE SUCCESSOR READS LINES WHERE THE SHELL READ FILES, and the reading is the
#   same reading. `input.tree.lines` is the committed bytes of a declared
#   `line_sources` path, which is what the shell's two positional arguments defaulted
#   to. The shell took those as arguments so a suite could point it at fixtures; the
#   successor's fixtures are whole repositories under
#   `crates/batten/tests/it/glob_containment.rs`, which is a stronger tier and not a
#   weaker one — it drives the compiled binary over a real tree rather than a
#   hand-written pair of files.
#
#   A CONFIG THIS READER PARSES NOTHING OUT OF IS NOT A CONFIG WITH NO INPUTS. It is
#   a parse that failed, and passing on it is the vacuous green a containment check
#   can most easily produce, so it is its own refusal.
#
#   COVERED MEANS present verbatim, or subsumed by a `P/**` entry whose prefix the
#   required glob starts with. That second clause is the whole reason the list can
#   stay short. It is deliberately NOT general glob subsumption, which is
#   undecidable in the directions that matter and would be a matcher this repository
#   would then have to own. A prefix test is the narrow, honest case; anything it
#   cannot prove must be listed verbatim, which fails CLOSED — the direction a
#   containment check has to fail in.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the uncovered glob and the line
#   of the config that demands it, never the rule's body.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.glob_containment

import rego.v1

rules contains "glob-containment"

config_path := "batten.toml"

hooks_path := "hk.pkl"

step_header := "  [\"batten-check\"]"

config_lines := lines if {
	lines := input.tree.lines[config_path]
}

hooks_lines := lines if {
	lines := input.tree.lines[hooks_path]
}

# --- which table a config line sits in ---------------------------------------
#
# A key's meaning is its TABLE's, not its spelling's: `path` appears under nine
# different tables here and only one of them makes a file an input. So each line
# resolves to the nearest header above it, which is the whole of TOML's scoping
# that this reader needs.
header_indices := {i |
	some i, line in config_lines
	startswith(line, "[")
}

table_of(i) := config_lines[j] if {
	above := {k |
		some k in header_indices
		k < i
	}
	j := max(above)
}

unquoted(text) := replace(text, "\"", "")

# --- what the config makes an input ------------------------------------------

required contains {"glob": glob, "line": i + 1} if {
	some i, line in config_lines
	table_of(i) == "[[rule]]"
	startswith(line, "glob = ")
	glob := trim_space(unquoted(substring(line, 7, -1)))
	glob != ""
}

required contains {"glob": glob, "line": i + 1} if {
	some i, line in config_lines
	table_of(i) == "[[budget.instructions.embedded]]"
	startswith(line, "path = ")
	glob := trim_space(unquoted(substring(line, 7, -1)))
	glob != ""
}

# The budget's own `files` array, gated as the one-line array it is in this
# config. A multi-line array would need continuation tracking, and the parse
# refusal below is what notices if one ever appears.
required contains {"glob": glob, "line": i + 1} if {
	some i, line in config_lines
	table_of(i) == "[budget.instructions]"
	startswith(line, "files = [")
	inner := substring(line, 9, indexof(line, "]") - 9)
	some raw in split(inner, ",")
	glob := trim_space(unquoted(raw))
	glob != ""
}

# --- what the hook step selects ----------------------------------------------
#
# The `glob = List(...)` belonging to the `["batten-check"]` step, and only that
# one: the manifest carries a dozen others. Bounded by the step's own header and
# the next step's, so a later step's list cannot be read as this step's.
step_start := i if {
	some i, line in hooks_lines
	startswith(line, step_header)
}

# The next step's header, or the end of the file when this step is the last one.
step_end := e if {
	after := {j |
		some j, line in hooks_lines
		j > step_start
		startswith(line, "  [\"")
	}
	e := min(after)
}

step_end := count(hooks_lines) if {
	step_start
	not next_step_exists
}

next_step_exists if {
	some j, line in hooks_lines
	j > step_start
	startswith(line, "  [\"")
}

glob_start := g if {
	within := {j |
		some j, line in hooks_lines
		j > step_start
		j < step_end
		contains(line, "glob =")
	}
	g := min(within)
}

# The list's last line: the first one at or after its opening that closes a
# paren. A COMMENT INSIDE THE LIST IS NOT LIST SYNTAX, and reading it as such made
# the retired gate lie — an entry's comment contained a parenthesised tracker key
# whose `)` ended the list early, so every entry below it read as uncovered. The
# skip below is why a comment cannot close the list, and skipping is deliberately
# preferred to being clever about the paren: mis-parsing in the REPORTING
# direction is survivable, the same parse silently dropping entries from
# `required` would not be.
glob_end := e if {
	closers := {j |
		some j, line in hooks_lines
		j >= glob_start
		j < step_end
		not comment_line(hooks_lines[j])
		contains(line, ")")
	}
	e := min(closers)
}

comment_line(line) if {
	startswith(trim_space(line), "//")
}

covered contains entry if {
	some j, line in hooks_lines
	j >= glob_start
	j <= glob_end
	not comment_line(line)
	some quoted in regex.find_n(data.batten.patterns["md-quoted-span"], line, -1)
	entry := unquoted(quoted)
	entry != ""
}

# --- containment --------------------------------------------------------------

satisfied(want) if {
	some have in covered
	have == want
}

satisfied(want) if {
	some have in covered
	endswith(have, "/**")
	startswith(want, substring(have, 0, count(have) - 2))
}

# THE PARSE REFUSALS, both of which fail closed rather than passing vacuously.
violation contains {
	"rule": "glob-containment",
	"verdict": "gate parse unread",
	"subjects": [{"path": config_path}],
} if {
	config_lines
	count(required) == 0
}

violation contains {
	"rule": "glob-containment",
	"verdict": "step declare missing",
	"subjects": [{"path": hooks_path}],
} if {
	hooks_lines
	count(required) > 0
	count(covered) == 0
}

violation contains {
	"rule": "glob-containment",
	"verdict": "manifest cover missing",
	"subjects": [{"path": sprintf("%s:%d", [config_path, entry.line])}],
} if {
	count(covered) > 0
	some entry in required
	not satisfied(entry.glob)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves
# `input.tree.lines` to the committed bytes of a declared `line_sources` path at
# all — a `with input as` block fabricates the very shape the engine may be unable
# to produce (CLOUD-845). `crates/batten/tests/it/glob_containment.rs` is that
# tier, and it drives the compiled binary over whole fixture repositories.

tree(config, hooks) := {"tree": {"lines": {"batten.toml": config, "hk.pkl": hooks}}}

step(entries) := array.concat(
	array.concat(["  [\"batten-check\"]"], entries),
	["  [\"other-step\"]"],
)

test_a_listed_glob_is_clean if {
	count(violation) == 0 with input as tree(
		["[[rule]]", "glob = \"crates/**/*.rs\""],
		step(["    glob = List(\"crates/**/*.rs\")"]),
	)
}

test_a_prefix_entry_subsumes_a_longer_glob if {
	count(violation) == 0 with input as tree(
		["[[rule]]", "glob = \"crates/batten/tests/**/*.rs\""],
		step(["    glob = List(\"crates/**\")"]),
	)
}

# Subsumption is a PREFIX test over a `P/**` entry, so a sibling prefix does not
# count — the direction a containment check must never fail in.
test_a_sibling_prefix_does_not_count if {
	some v in violation with input as tree(
		["[[rule]]", "glob = \"crates-extra/**/*.rs\""],
		step(["    glob = List(\"crates/**\")"]),
	)
	v.verdict == "manifest cover missing"
}

# And the `/**` is what makes an entry a prefix at all: an entry without it
# subsumes nothing, however much of it a required glob happens to start with.
test_a_slashless_entry_does_not_subsume if {
	some v in violation with input as tree(
		["[[rule]]", "glob = \"crates-extra/**/*.rs\""],
		step(["    glob = List(\"crates\")"]),
	)
	v.verdict == "manifest cover missing"
}

test_an_unlisted_glob_is_refused if {
	some v in violation with input as tree(
		["[[rule]]", "glob = \"policy/**/*.rego\""],
		step(["    glob = List(\"crates/**\")"]),
	)
	v.verdict == "manifest cover missing"
}

# The failure the retired gate actually shipped: a comment inside the list closed
# it early and every entry below read as uncovered.
test_a_comment_inside_the_list_does_not_close_it if {
	count(violation) == 0 with input as tree(
		["[[rule]]", "glob = \"policy/**/*.rego\""],
		step([
			"    glob = List(",
			"      // the rule that makes this an input (see the tracker)",
			"      \"policy/**/*.rego\",",
			"    )",
		]),
	)
}

test_a_budget_files_entry_is_an_input if {
	some v in violation with input as tree(
		["[budget.instructions]", "files = [\"AGENTS.md\"]"],
		step(["    glob = List(\"crates/**\")"]),
	)
	v.verdict == "manifest cover missing"
}

test_an_embedded_budget_path_is_an_input if {
	some v in violation with input as tree(
		["[[budget.instructions.embedded]]", "path = \"rules/rust.md\""],
		step(["    glob = List(\"crates/**\")"]),
	)
	v.verdict == "manifest cover missing"
}

# A `path` key belongs to its table, not to its spelling: eight other tables in
# this config carry one and none of them makes a file an input.
test_a_path_under_another_table_is_not_an_input if {
	count(violation) == 0 with input as tree(
		["[[rule]]", "glob = \"crates/**\"", "[[waiver]]", "path = \"some/waived.yml\""],
		step(["    glob = List(\"crates/**\")"]),
	)
}

# A later step's list cannot be read as this step's.
test_a_following_steps_list_is_not_this_steps if {
	some v in violation with input as tree(
		["[[rule]]", "glob = \"policy/**\""],
		array.concat(
			["  [\"batten-check\"]", "    glob = List(\"crates/**\")", "  [\"other-step\"]"],
			["    glob = List(\"policy/**\")"],
		),
	)
	v.verdict == "manifest cover missing"
}

# A glob-less step runs on every commit, which is what the trigger removed — so
# its absence is a regression, not a default.
test_a_step_with_no_glob_list_is_refused if {
	some v in violation with input as tree(
		["[[rule]]", "glob = \"crates/**\""],
		["  [\"batten-check\"]", "  [\"other-step\"]"],
	)
	v.verdict == "step declare missing"
}

# A config this reader parses nothing out of is a failed parse, never a config
# with no inputs.
test_a_config_yielding_no_inputs_is_refused if {
	some v in violation with input as tree(
		["# nothing but prose"],
		step(["    glob = List(\"crates/**\")"]),
	)
	v.verdict == "gate parse unread"
}

#MUTANT-SUITE crates/batten/tests/it/glob_containment.rs
#MUTANT uncovered-glob-unread|s@^\tnot satisfied(entry.glob)$@\tfalse@|an_unlisted_glob_is_refused_and_named
#MUTANT prefix-subsumption-unbounded|s@^\tendswith(have, "/\*\*")$@\ttrue@|a_slashless_entry_does_not_subsume_by_prefix
