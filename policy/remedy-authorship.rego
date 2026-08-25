# A gate's remedy reaches its reader, and exactly one authority writes it.
#
# CLOUD-1050 defects A and B, as a predicate. Both were measured on
# `prose-only-check` in one session, and together they MANUFACTURE the CLOUD-680
# shape: strip the routes a reader can act on and the override is the only
# concrete arm left, so an incomplete remedy does not merely fail to redirect —
# it produces the override ask. That is why these are one module: they are one
# failure with two causes, and a tree that fixed either alone still produces it.
#
# WHY REGO AND NOT A BATS SUITE, stated because the obvious instrument is the
# wrong one here. The defect is in a shell gate, so a shell test over that gate
# is the reflex — and it would be new shell shipped to gate a shell defect, in a
# tree whose whole campaign is retiring shell gates (CLOUD-843). Nothing needed
# building for this: `Fact::Lines` (CLOUD-846) already puts `path -> the file's
# lines` in front of a module, and `input.tree.documents` already carries the
# parsed manifest. Both predicates below are pure text over facts that exist.
#
# ─── A: THE REMEDY IS ON THE CHANNEL THE READER ACTUALLY READS ───────────────
#
# `land` echoes a step's last words through an `::error::` filter, and so does
# every reader following this tree's convention. A refusal line without the
# prefix is not quiet, it is ABSENT. Measured in one land log: line 777 the
# diagnosis (prefixed), line 780 the correct remedy (unprefixed, and the only
# line of that refusal missing it), line 782 a paraphrase (prefixed). The reader
# received a diagnosis and a paraphrase and never received the route.
#
# THE PREDICATE IS SCOPED TO WHAT IT CAN DECIDE HONESTLY: a line inside a brace
# group redirected to `>&2`. That is a refusal block by construction — a program
# writes to stderr to be read as a complaint — and it is syntactically findable
# without parsing shell. Lines a gate writes to stderr by other spellings are
# NOT judged, and that is a stated limit rather than an oversight: a predicate
# that guessed at them would fire on `exec 2>`, on logging, and on every
# heredoc, and a gate nobody can keep green gets switched off.
#
# ─── B: ONE AUTHORITY FOR THE REMEDY, NEVER A CALLER'S COPY ──────────────────
#
# A caller that restates a gate's remedy is a second authority, and a second
# authority drifts. Measured: `verify` dropped the fold-it-in route and turned
# the override's precondition into bookkeeping, leaving a binary whose only
# concrete arm was the bypass.
#
# The computable half of "don't restate it" is NAMING THE BYPASS. A caller has
# no business printing a gate's override variable: it does not implement it, it
# cannot state its precondition, and the variable's presence in a caller's
# message is what makes the bypass the cheapest concrete thing in reach. So the
# rule is: a `mise.toml` task body may name a `BATTEN_*` bypass only if that
# task's own program reads it. `linear-check`'s "see its message" is the idiom
# this leaves standing, and it cannot drift because it carries no routes.
#
# WHAT NEITHER PREDICATE CLAIMS. Whether a remedy is CLEAR, whether its route is
# the cheapest, and whether its wording steers well are judgements, and
# non-negotiable rule 3 keeps a gate off them. These decide two mechanical
# facts: did the line go where it would be read, and does exactly one program
# author it.
#
#MUTANT remedy-prefix-unchecked|s@not startswith(emitted(line), "::error::")@false@|a refusal line outside the error channel is refused
#MUTANT remedy-judges-the-source-line|s@text := trim_left(trim_space(substring(trimmed, count(verb), -1)), "\\"'")@text := trimmed@|a fully prefixed block passes
#MUTANT remedy-block-unbounded|s@stderr_block\[path\]\[i\]@lines_of[path][i]@|a line outside a stderr block is not judged
#MUTANT bypass-author-unchecked|s@not implements_bypass(name, var)@false@|a caller naming a bypass it does not implement is refused
#MUTANT bypass-implementer-ignored|s@some l in task_program_lines(name)@some l in []@|the task that implements a bypass may name it
#
# The rows above declare what each predicate must not survive; what CANNOT run
# them is the mutation runner, for a reason that is a named gap rather than a
# choice. `mutant` resolves a gate's suite as `tests/$gate.bats`, and a policy
# module has none — the second tier here is `crates/batten/tests/remedy_
# authorship.rs`, which drives the compiled binary and is the stronger evidence,
# but it is not what `mutant` drives. `batten policy test` IS wired as of
# CLOUD-931 and runs the load-time tier below; that tier is `with input as`
# cases, which fabricate their own input and are exactly what a mutation runner
# should not be pointed at.
#MUTANT-EXEMPT CLOUD-931|no `tests/remedy-authorship.bats` exists: `mutant` resolves a gate's suite as `tests/$gate.bats`, so without one there is no named case a mutation could turn red. `batten policy test` IS wired as of CLOUD-931, but that is the load-time tier and a `with input as` case is not what the mutation runner drives

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.remedy_authorship

import rego.v1

rules contains "remedy-reaches-the-reader"

rules contains "remedy-has-one-author"

# ---------------------------------------------------------------------------
# A: every line of a stderr block carries the error prefix.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "remedy-reaches-the-reader",
	"verdict": "V-REMEDY-DROPPED-BY-THE-FILTER",
	"subjects": [{"path": path, "line": i + 1}],
} if {
	some path, block in stderr_block
	some i, line in block
	emits_a_literal(line)
	not startswith(emitted(line), "::error::")
}

# The lines of every tracked file the run acquired. `input.tree.missing` is the
# could-not-look set and is deliberately NOT folded in here: a file the engine
# could not read yields no finding rather than a clean one, which is the
# distinction CLOUD-251 keeps and a vacuous pass would lose.
lines_of[path] := ls if {
	some path, ls in input.tree.lines
}

# Lines inside a `{ ... } >&2` group, keyed by path and by their index in the
# file, so a finding can name the real line number.
#
# The scan is a fold Rego has no spelling for, so it is expressed as: a line is
# inside a block when some `{` opener above it has not yet met its `} >&2`
# closer. Same shape as `run-shape.rego`'s heredoc scan, and chosen for the same
# reason — it keeps this a comprehension.
stderr_block[path][i] := line if {
	some path, ls in lines_of
	endswith(path, ".sh")
	some i, line in ls
	some j in openers_for(path)
	j < i
	closes_to_stderr(path, j, i)
}

# Every bare `{` on its own line: a brace group opener. A `{` in any other
# position is a parameter expansion, a brace expansion, or a literal, and is not
# a group — which is why the whole trimmed line must be the brace.
openers_for(path) := [j |
	some j, line in lines_of[path]
	trim_space(line) == "{"
]

# The group opened at `j` is still open at `i`, and its closer redirects to
# stderr. A closer between them ends the group; the FIRST one is what counts.
closes_to_stderr(path, j, i) if {
	some k in numbers.range(j + 1, count(lines_of[path]) - 1)
	k > i
	startswith(trim_space(lines_of[path][k]), "}")
	contains(lines_of[path][k], ">&2")
	not closed_before(path, j, i)
}

closed_before(path, j, i) if {
	some k in numbers.range(j + 1, i)
	startswith(trim_space(lines_of[path][k]), "}")
}

# The TEXT a line puts in front of a reader, not the line itself. This
# distinction is the predicate: an earlier draft tested whether the SOURCE line
# started with `::error::`, which no `echo "::error:: …"` ever does, so a
# correctly prefixed refusal was refused. The load-time suite caught it — the
# reason a module carries one.
#
# The leading quote is trimmed rather than split on, so both spellings the tree
# actually uses resolve the same way: `echo "::error:: …"` and
# `printf '::error:: %s\n'` (which is `board-payloads`' form).
emitted(line) := text if {
	some verb in {"echo ", "printf "}
	trimmed := trim_space(line)
	startswith(trimmed, verb)
	text := trim_left(trim_space(substring(trimmed, count(verb), -1)), "\"'")
}

# A line that puts a literal in front of a reader. A variable-only `echo "$msg"`
# carries no prose this gate can judge — the prose is wherever the variable was
# assigned, which is not this line's fact — and a bare `echo` is a blank line.
emits_a_literal(line) if {
	text := emitted(line)
	text != ""
	not startswith(text, "$")
}

# ---------------------------------------------------------------------------
# B: only the program that implements a bypass may name it.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "remedy-has-one-author",
	"verdict": "V-REMEDY-HAS-TWO-AUTHORS",
	"subjects": [{"artifact": name}, {"artifact": var}],
} if {
	some name, body in task_bodies
	some var in bypass_names(body)
	not implements_bypass(name, var)
}

task_bodies[name] := body if {
	some name, task in input.tree.documents["mise.toml"].tasks
	body := task_run(task)
}

# A task's body is `run`, which is a string or a list of strings.
task_run(task) := concat("\n", task.run) if is_array(task.run)

task_run(task) := task.run if is_string(task.run)

# Every `BATTEN_*` name a body mentions. Split on the prefix and take the
# leading identifier of each tail: the prefix itself is the separator, so the
# first piece is whatever preceded the first mention and is skipped.
bypass_names(body) := {var |
	some i, tail in split(body, "BATTEN_")
	i > 0
	var := concat("", ["BATTEN_", substring(tail, 0, head_len(tail))])
	is_a_bypass(var)
}

# A TOKEN SPLIT, NOT A CHARACTER SCAN, and the history is the argument for it.
# The first draft walked the tail character by character, keeping the leading
# identifier with a prefix predicate. It cost three regorus faults that neither
# `opa check` nor `regal lint` saw — a bare fact rule refused at LOAD, then
# `numbers.range(0, -1)` counting DOWN into `substring(s, -1, 1)`, then
# "statements not scheduled in query" on the comprehension that called the
# prefix predicate. Each was found only by running the real engine over the real
# tree.
#
# Normalising the separators and splitting is the same predicate with none of
# that surface: a shell body's variable references are delimited by exactly
# these characters, so a `BATTEN_*` name falls out as a whole token. Simpler is
# not a style preference here — it is the difference between a module that loads
# and one that type checks.
separators := ["=", " ", "\"", "'", "{", "}", "(", ")", ":", ";", ",", "$", "\n", "\t", "/"]

# Where the name ends: the NEAREST separator after it, or the end of the tail if
# there is none. `min` over a comprehension is total and non-recursive — a fold
# that normalised the string first is neither, and Rego rejects it outright
# (`rego_recursion_error`), which is the fourth thing this predicate was written
# three ways to satisfy.
head_len(tail) := m if {
	ends := [at |
		some sep in separators
		at := indexof(tail, sep)
		at >= 0
	]
	m := min(array.concat(ends, [count(tail)]))
}

# A bypass, not merely a `BATTEN_*` name: the tree's hatches end in one of these
# words. `BATTEN_TRANSCRIPT_FILE` and the rest of the injection surface are
# configuration, and naming them in a caller is not a second remedy.
is_a_bypass(var) if {
	some suffix in {"_BYPASS", "_OVERRIDE", "_OVERLAP", "_TAKEOVER"}
	endswith(var, suffix)
}

# The task that implements the bypass is the one whose own program READS it —
# dereferences it, rather than merely spelling its name.
#
# THE DEREFERENCE IS THE WHOLE PREDICATE, and a plain `contains` made this rule
# VACUOUS. `task_program_lines` includes the task's own body, and `bypass_names`
# found the name IN that body, so a substring test was satisfied by the very
# mention it was meant to judge: the rule could never fire, on any input. Its own
# load-time case is what caught that — a gate that refuses nothing and a clean
# tree are byte-identical on the decision surface, so nothing else would have.
#
# `$VAR` and `${VAR` are the two spellings a shell read takes. A caller that
# writes `set BATTEN_X=1 to record the exception` is telling a reader about
# somebody else's hatch, which is exactly defect B; the gate that owns the hatch
# writes `[[ -n "${BATTEN_X:-}" ]]` and is untouched.
implements_bypass(name, var) if {
	some l in task_program_lines(name)
	some form in [sprintf("$%s", [var]), sprintf("${%s", [var])]
	contains(l, form)
}

# A task's program: the file task of the same name if there is one, plus the
# body itself, since a body may implement its own hatch inline.
task_program_lines(name) := ls if {
	ls := array.concat(
		object.get(lines_of, sprintf("mise-tasks/%s.sh", [name]), []),
		split(object.get(task_bodies, name, ""), "\n"),
	)
}

# ---------------------------------------------------------------------------
# Load-time tests (CLOUD-835). These are the load-time half ONLY: what proves
# this gate decides is `crates/batten/tests/remedy_authorship.rs`, which drives
# the compiled binary over a real tree, because a `with input as` fabricates its
# own input and can be green over a shape the engine never produces (CLOUD-845).
# ---------------------------------------------------------------------------

test_an_unprefixed_stderr_line_is_refused if {
	some v in violation with input as {"tree": {"lines": {"mise-tasks/g.sh": [
		"{",
		"\techo \"::error:: it broke\"",
		"\techo \"here is the fix\"",
		"} >&2",
	]}}}
	v.rule == "remedy-reaches-the-reader"
}

test_a_fully_prefixed_block_passes if {
	count(violation) == 0 with input as {"tree": {"lines": {"mise-tasks/g.sh": [
		"{",
		"\techo \"::error:: it broke\"",
		"\techo \"::error:: here is the fix\"",
		"} >&2",
	]}}}
}

# THE ANTI-WIDENING ARM. A block NOT redirected to stderr is ordinary output —
# a summary line, a count — and judging it would fire on every task in the tree.
test_a_block_not_redirected_to_stderr_is_not_judged if {
	count(violation) == 0 with input as {"tree": {"lines": {"mise-tasks/g.sh": [
		"{",
		"\techo \"recovered 2 of 2\"",
		"}",
	]}}}
}

test_a_caller_naming_a_bypass_it_does_not_read_is_refused if {
	some v in violation with input as {"tree": {"documents": {"mise.toml": {"tasks": {"verify": {"run": "echo \"set BATTEN_PROSE_ONLY_OVERRIDE=1 to record the exception\""}}}}}}
	v.rule == "remedy-has-one-author"
}

# THE DISCRIMINATING CASE for B: the gate that OWNS a hatch must be able to name
# it, or the rule bans the only honest mention there is.
test_the_task_that_implements_a_bypass_may_name_it if {
	count(violation) == 0 with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {"prose-only-check": {"run": "mise-tasks/prose-only-check.sh"}}}},
		"lines": {"mise-tasks/prose-only-check.sh": ["if [[ -n \"${BATTEN_PROSE_ONLY_OVERRIDE:-}\" ]]; then"]},
	}}
}

# Configuration is not a bypass, so naming it is not a second remedy.
test_a_non_bypass_batten_variable_is_not_judged if {
	count(violation) == 0 with input as {"tree": {"documents": {"mise.toml": {"tasks": {"board-payloads": {"run": "BATTEN_TRANSCRIPT_FILE=x mise-tasks/board-payloads.sh"}}}}}}
}
