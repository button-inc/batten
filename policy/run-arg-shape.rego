# A task body that reads a positional argument it can never receive (CLOUD-1916).
#
# mise APPENDS a task's arguments to its `run` string; it does not set `$1`. So a
# bare body reading `${1:-default}` always takes the default, and the caller's
# argument lands as trailing words on the body's LAST command. Measured twice:
# `ci-slow-needed` compared the wrong range on #928, and `darwin-link` linked —
# and receipted — aarch64 on the `darwin-link (x86_64-apple-darwin)` required
# check, which therefore never linked its own target. Both fixes are the same
# shape: wrap the body in a function and call it last, so the appended words are
# the function's arguments.
#
# A STATE RULE, NOT A RATCHET, and that is measured rather than preferred: on
# landing, every `run = "` line in `mise.toml` that reads a positional is already
# function-shaped (four: `ci-slow-needed`, `darwin-link`, `task-registry`,
# `singleton`), so the rule's first run refuses nothing and there is no legacy
# population for an exception to grow around — the reason `cfg-gated-test.rego`
# had to be a ratchet does not hold here.
#
# THE RESIDUE IS NAMED. Only a one-line `run = "` body is read: a `'''` body or a
# `file =` script reads its arguments differently and is out of scope. An awk
# field reference (`$1` inside a quoted awk program) in a bare body would be
# refused; none exists, and a body carrying one can be function-shaped at no cost.
#
# NO INLINE REGEX, on `cfg-gated-test.rego`'s precedent: every test is a string
# builtin over one line.
#MUTANT-SUITE crates/batten/tests/it/run_arg_shape.rs
#MUTANT bare-body-arg-admitted|s@^\tnot function_shaped(line)$@\tfalse@|a_bare_body_reading_its_first_argument_is_refused
package batten

import rego.v1

rules contains "task read unseen"

run_prefix := "run = \""

# The references mise's appending can never satisfy in a bare body.
positionals := ["$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "${1", "${2", "${3", "${4", "${5", "${6", "${7", "${8", "${9", "$@", "${@", "$*"]

reads_positional(line) if {
	some p in positionals
	contains(line, p)
}

# `run = "name() {` — the body's first word declares a function, which is the
# shape whose appended words become arguments.
function_shaped(line) if {
	rest := substring(trim_space(line), count(run_prefix), -1)
	head := split(rest, " ")[0]
	endswith(head, "()")
}

bare_reader(line) if {
	startswith(trim_space(line), run_prefix)
	reads_positional(line)
	not function_shaped(line)
}

violation contains {
	"rule": "task read unseen",
	"verdict": "task read dropped",
	"subjects": [{"path": "mise.toml"}, {"artifact": sprintf("mise.toml:%d", [index + 1])}],
} if {
	some index, line in input.tree.lines["mise.toml"]
	bare_reader(line)
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------

lines(ls) := {"tree": {"lines": {"mise.toml": ls}}}

test_the_pre_fix_darwin_link_body_is_refused if {
	count(violation) == 1 with input as lines(["run = \"t=\\\"${1:-${DARWIN_TARGET:-aarch64-apple-darwin}}\\\"; echo $t\""])
}

test_a_bare_dollar_one_is_refused if {
	count(violation) == 1 with input as lines(["run = \"git diff $1 $2\""])
}

test_the_function_shaped_body_passes if {
	count(violation) == 0 with input as lines(["run = \"darwin_link() { t=\\\"${1:-x}\\\"; echo $t; }; darwin_link\""])
}

test_a_body_with_no_positional_passes if {
	count(violation) == 0 with input as lines(["run = \"cargo run --quiet -p batten -- doctor target\""])
}

test_a_comment_naming_the_shape_is_not_a_body if {
	count(violation) == 0 with input as lines(["# NO `\"$1\"`: mise appends a task's positional arguments"])
}

test_no_mise_toml_is_silent if {
	count(violation) == 0 with input as {"tree": {"lines": {}}}
}
