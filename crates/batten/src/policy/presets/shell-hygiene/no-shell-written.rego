# A write that authors shell is refused at the write (CLOUD-2335).
#
# The tree arms in this preset judge shell once it is in the tree, at `verify`;
# an agent writing a shell file heard nothing until then. This arm refuses the
# write itself: one that creates a shell-named file, or that puts a shell shebang
# on line 1 of a file whose line 1 named none.
#
# WHAT COUNTS IS NOT THIS MODULE'S TO DECIDE. `input.facts["shell-introduced"]`
# is decided in Rust by the one detector the census and the tree arms share
# (`crates/batten/src/shell.rs`): `look` is `is`, `is-not` or `could-not-look`,
# and `reason` says which arm, `shell-path` or `shebang`. The content a write
# would land never reaches this document (non-negotiable rule 4), so no
# extension or shebang list is restated here.
#
# COULD-NOT-LOOK ABSTAINS: a notebook cell, a file over the read bound, a host
# whose write keys the engine does not read. An overwrite that keeps an existing
# shebang is `is-not`, because the tree arms own shell already there.
#
# The agent's own Bash calls are never judged here: the ban covers what the
# repository commits, never the tool calls that build it.
#
# Names no repository and no file: true of the practice, which is what a vendored
# preset may contain (non-negotiable rule 1).

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: reads `input.call.operation`,
#   `input.call.writes` and `input.facts["shell-introduced"]`, never the tree.
#   THE BRACKETS ARE NOT STYLE: the fact and the schema carry hyphens, so the
#   dotted form is a parse error.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.shell_written

import rego.v1

rules contains "shell write refused"

violation contains {
	"rule": "shell write refused",
	"verdict": "shell write refused",
	"subjects": [{"path": input.call.writes}],
} if {
	input.call.operation == "write"
	is_string(input.call.writes)
	input.facts["shell-introduced"].look == "is"
}

test_a_created_shell_path_is_refused if {
	some v in violation with input as {
		"call": {"operation": "write", "writes": "x.sh"},
		"facts": {"shell-introduced": {"look": "is", "reason": "shell-path"}},
	}
	v.rule == "shell write refused"
	v.subjects == [{"path": "x.sh"}]
}

test_a_shebang_put_on_line_one_is_refused if {
	some v in violation with input as {
		"call": {"operation": "write", "writes": "x.txt"},
		"facts": {"shell-introduced": {"look": "is", "reason": "shebang"}},
	}
	v.rule == "shell write refused"
}

test_a_write_introducing_nothing_is_admitted if {
	count(violation) == 0 with input as {
		"call": {"operation": "write", "writes": "x.txt"},
		"facts": {"shell-introduced": {"look": "is-not", "reason": null}},
	}
}

test_could_not_look_abstains if {
	count(violation) == 0 with input as {
		"call": {"operation": "write", "writes": "big.txt"},
		"facts": {"shell-introduced": {"look": "could-not-look", "reason": null}},
	}
}

# Not a write: a Bash call is never judged here, whatever the fact says.
test_a_bash_call_is_never_refused if {
	count(violation) == 0 with input as {
		"call": {"operation": "run", "writes": null, "command": "sh -c true"},
		"facts": {"shell-introduced": {"look": "is", "reason": "shebang"}},
	}
}

test_a_write_naming_no_path_is_not_refused if {
	count(violation) == 0 with input as {
		"call": {"operation": "write", "writes": null},
		"facts": {"shell-introduced": {"look": "is", "reason": "shell-path"}},
	}
}
