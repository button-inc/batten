# Every tool version named in `.mcp.json` agrees with `mise.toml`'s pin, and
# every `mise exec` launch is scoped (CLOUD-316, migrated under CLOUD-910).
#
# `.mcp.json` NAMES the tool it launches — `mise exec "pipx:serena-agent@1.6.1"
# -- serena …` — because a bare `mise exec` provisions the whole toolchain before
# exec'ing anything, so one unrelated tool failing to install takes the server
# down with it. Scoping the exec is the fix.
#
# It buys that at the cost of writing a pinned version down twice. `mise.toml`
# owns the pin (it is what `mise install` and `mise.lock` read); `.mcp.json`'s
# copy is a REFERENCE to it. When the two disagree the failure is not a version
# mismatch, it is worse: `mise exec` treats the named version as a request and
# installs it, so a bump in `mise.toml` leaves the MCP server silently running the
# OLD version, with `mise.lock`, the SBOM and every other consumer describing the
# new one. Nothing surfaces that — the server starts fine.
#
# ─── WHY THIS IS A MODULE AND NOT A PRESET ───────────────────────────────────
#
# The predicate names a task RUNNER's pin table (`[tools]` in `mise.toml`) and a
# specific host's server manifest (`.mcp.json`). Neither survives having "the
# consumer's facts" pulled out — what would remain is "two documents agree about a
# string", which decides nothing. So this is an in-repo module by CLOUD-910's
# default, and non-negotiable rule 1 is why it may name those files at all.
#
# ─── THE SHAPE HALF IS THE ONE THE ISSUE IS ABOUT ────────────────────────────
#
# The pin exists because the exec is SCOPED. Reverting to a bare `mise exec --`
# would remove every reference below and leave a version-only predicate reporting
# "nothing to check" — green, with the defect restored. Checking only the versions
# would gate the cost of the fix and not the fix.
#
# SELECTED BY ARGV, NOT BY `command`. The command is no longer always `mise`:
# CLOUD-714 interposes `mise-tasks/<server>-mcp`, a shim that records the spawn and
# `exec`s `mise "$@"` with these same args. Keying on `command == "mise"` would
# have made that shim silently exempt — the gate reporting a clean pass while the
# property it exists for went unchecked. `args[0] == "exec"` is what actually
# identifies a mise exec launch, shim or no.
#
# ─── A PIN IS THE PLAIN STRING FORM, AND ONLY THAT ───────────────────────────
#
# `[tools]` admits a bare version string and a table (`{ version = "…" }`). The
# bash this replaces read only the quoted-string form, so a table-valued entry
# read as "carries no pin at all". That is preserved rather than quietly widened:
# widening it would be a verdict change wearing a migration's clothes, and
# CLOUD-910 says a gate whose verdict must change is a `changed` mapping arm with
# its reason. Two entries in this tree are tables today (`rust`, `npm:renovate`)
# and neither is referenced from `.mcp.json`, so the clause is inert here and is
# stated so the next author does not "fix" it into a behaviour change.
#
# ─── COULD NOT LOOK IS NOT A PASS, AND ONLY THE AUTHORITY IS LOUD ────────────
#
# `mise.toml` carries the pins, so a tree that could not read it cannot judge a
# single reference — that is loud. `.mcp.json` is different: a tree with no server
# manifest has nothing to check, which is the bash's own `exit 0`, so its absence
# is not-applicable rather than could-not-look. `command-task-defined.rego` draws
# the same line between the two absences for the same reason.
#
#MUTANT pin-disagreement-passes|s@have != want@false@|a version .mcp.json names that mise.toml does not pin fails, naming both
#MUTANT unpinned-tool-passes|s@not is_string(pins[tool])@false@|a tool mise.toml does not carry at all fails
#MUTANT unscoped-exec-passes|s@scoped_operands(args) == 0@false@|a bare `mise exec` fails even though it names no version to compare
#MUTANT authority-absence-is-silent|s@some path in input.tree.missing@false@|a missing mise.toml cannot be compared against
#
#MUTANT-EXEMPT CLOUD-910|no `tests/mise-pin-agreement.bats` exists and none may: this row is part of the change that retires bats suites onto the engine, so a suite named for it is exactly what `policy/shell-retirement.rego`'s `V-SHELL-RULE-ADDED` refuses — and `$MUTANT_GATES` lives in `mise.toml`, which is outside this PR's file domain. `mutant` resolves a gate's suite as `tests/$gate.bats` and nothing else, so a module whose second tier is a Rust test cannot be enforced by it. The second tier is `crates/batten/tests/mise_pin_agreement.rs`, which drives the compiled binary over a real tree; the declared rows above name the mutations that tier catches.

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.mise_pin_agreement

import rego.v1

rules contains "mise-pin-agreement"

# ---------------------------------------------------------------------------
# The two documents, bound through rules so every predicate below is UNDEFINED
# rather than vacuously clean when one of them was not read.
# ---------------------------------------------------------------------------

manifest := doc if {
	doc := input.tree.documents[".mcp.json"]
	is_object(doc)
}

pins := tools if {
	tools := input.tree.documents["mise.toml"].tools
	is_object(tools)
}

servers := s if {
	s := manifest.mcpServers
	is_object(s)
}

# ---------------------------------------------------------------------------
# Every `backend:tool@version` reference a server's argv carries.
#
# Deliberately general over `.mcp.json` rather than special-cased to one server:
# any server whose args carry the triple is checked, so a second MCP server added
# the same way inherits the gate without anyone remembering to widen it.
# ---------------------------------------------------------------------------

reference contains {"server": server, "ref": arg, "tool": tool, "want": want} if {
	some server, body in servers
	some arg in body.args
	is_string(arg)
	regex.match(data.batten.patterns["mise-tool-reference"], arg)

	# SPLIT AT THE LAST `@`, which is what the bash's `${ref%@*}` / `${ref##*@}`
	# pair does. A version can carry no `@`; a tool name can, and joining the head
	# back together is what keeps such a name whole.
	parts := split(arg, "@")
	want := parts[count(parts) - 1]
	tool := concat("@", array.slice(parts, 0, count(parts) - 1))
}

# ---------------------------------------------------------------------------
# A: the pin the reference names disagrees with the authority's.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "mise-pin-agreement",
	"verdict": "V-MCP-PIN-DISAGREES",
	"subjects": [{"path": ".mcp.json"}, {"artifact": entry.server}, {"artifact": entry.ref}],
} if {
	some entry in reference
	have := pins[entry.tool]
	is_string(have)
	have != entry.want
}

# ---------------------------------------------------------------------------
# B: the authority carries no pin for the tool the reference names.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "mise-pin-agreement",
	"verdict": "V-MCP-PIN-UNDECLARED",
	"subjects": [{"path": ".mcp.json"}, {"artifact": entry.server}, {"artifact": entry.ref}],
} if {
	some entry in reference
	tool := entry.tool

	# A table-valued entry is not a pin this rule can compare, and it is spelled
	# the same way an absent one is. See the header: preserved from the bash
	# rather than widened here.
	not is_string(pins[tool])
}

# ---------------------------------------------------------------------------
# C: a `mise exec` launch that names no tool before `--`.
#
# THIS IS THE REGRESSION THE ISSUE IS ACTUALLY ABOUT. It must not read as
# "nothing to check".
# ---------------------------------------------------------------------------

violation contains {
	"rule": "mise-pin-agreement",
	"verdict": "V-MCP-EXEC-UNSCOPED",
	"subjects": [{"path": ".mcp.json"}, {"artifact": server}],
} if {
	some server, body in servers
	args := body.args
	args[0] == "exec"
	scoped_operands(args) == 0
}

# Everything between `exec` and the first `--` is what the launch is scoped to. A
# bare exec has nothing between them.
scoped_operands(args) := count([operand |
	some i, operand in args
	i > 0
	i < terminator(args)
])

# The index of the first `--`, or one past the end when there is none — so a
# launch that never terminates mise's own argv still counts its operands.
terminator(args) := at if {
	candidates := [i | some i, word in args; word == "--"]
	count(candidates) > 0
	at := candidates[0]
}

terminator(args) := count(args) if {
	every word in args {
		word != "--"
	}
}

# ---------------------------------------------------------------------------
# D: could not look at the AUTHORITY.
#
# `mise.toml` carries the pins, so its absence means no reference can be judged.
# `.mcp.json`'s absence is not-applicable and is deliberately silent — see the
# header. Only fires where there is something that WOULD have been judged, which
# is what keeps a tree that merely holds a copy of this config out of it.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "mise-pin-agreement",
	"verdict": "V-PIN-AUTHORITY-UNREADABLE",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	endswith(path, "mise.toml")
	manifest
}

# --- cases -----------------------------------------------------------------
#
# The load-time tier. `crates/batten/tests/mise_pin_agreement.rs` is the tier that
# proves the ENGINE builds the shape these fabricate.

scoped_tree(version) := {"tree": {
	"documents": {
		".mcp.json": {"mcpServers": {"serena": {
			"command": "mise-tasks/serena-mcp.sh",
			"args": ["exec", sprintf("pipx:serena-agent@%s", [version]), "--", "serena", "start-mcp-server"],
		}}},
		"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1", "uv": "0.8"}},
	},
	"missing": [],
}}

test_a_scoped_launch_whose_version_matches_passes if {
	count(violation) == 0 with input as scoped_tree("1.6.1")
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}

test_a_version_the_authority_pins_differently_is_refused if {
	found := violation with input as scoped_tree("9.9.9")
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	count(found) == 1
	some finding in found
	finding.verdict == "V-MCP-PIN-DISAGREES"
}

test_a_tool_the_authority_does_not_carry_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"other": {"args": ["exec", "pipx:nothing@1.0", "--", "x"]}}},
			"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1"}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	count(found) == 1
	some finding in found
	finding.verdict == "V-MCP-PIN-UNDECLARED"
}

# THE REGRESSION. A bare exec names no version to compare, and must not pass.
test_a_bare_exec_is_refused_even_though_it_names_no_version if {
	found := violation with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"serena": {"args": ["exec", "--", "serena", "start-mcp-server"]}}},
			"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1"}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	count(found) == 1
	some finding in found
	finding.verdict == "V-MCP-EXEC-UNSCOPED"
}

test_a_server_not_launched_through_mise_is_left_alone if {
	count(violation) == 0 with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"thing": {"command": "npx", "args": ["-y", "some-server"]}}},
			"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1"}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}

# THE SELECTOR IS ARGV, NOT THE COMMAND NAME (CLOUD-714). A shimmed launch is
# still checked; keying on `command == "mise"` would exempt every one of them.
test_a_shimmed_bare_exec_is_still_refused if {
	found := violation with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"serena": {
				"command": "mise-tasks/serena-mcp.sh",
				"args": ["exec", "--", "serena", "start-mcp-server"],
			}}},
			"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1"}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	count(found) == 1
	some finding in found
	finding.verdict == "V-MCP-EXEC-UNSCOPED"
}

# A shimmed launch that IS scoped passes, and its pin is still read.
test_a_shimmed_scoped_launch_passes_and_its_pin_is_read if {
	count(violation) == 0 with input as scoped_tree("1.6.1")
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}

# An absent server manifest is nothing to check — the bash's own `exit 0`.
test_an_absent_server_manifest_is_not_reported if {
	count(violation) == 0 with input as {"tree": {
		"documents": {"mise.toml": {"tools": {"pipx:serena-agent": "1.6.1"}}},
		"missing": [".mcp.json"],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}

# An absent AUTHORITY is loud: it carries the pins, so no reference can be judged.
test_an_absent_authority_is_loud if {
	found := violation with input as {"tree": {
		"documents": {".mcp.json": {"mcpServers": {"serena": {"args": ["exec", "pipx:serena-agent@1.6.1", "--", "serena"]}}}},
		"missing": ["mise.toml"],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	some finding in found
	finding.verdict == "V-PIN-AUTHORITY-UNREADABLE"
}

# ANTI-VACUITY for the clause above: with no manifest there is nothing that would
# have been judged, so an absent authority is not this rule's finding either.
test_an_absent_authority_with_no_manifest_is_silent if {
	count(violation) == 0 with input as {"tree": {
		"documents": {},
		"missing": ["mise.toml", ".mcp.json"],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}

# A TABLE-VALUED PIN IS NOT A PIN THIS RULE COMPARES, preserved from the bash's
# quoted-string-only read rather than widened here.
test_a_table_valued_pin_reads_as_undeclared if {
	found := violation with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"r": {"args": ["exec", "npm:renovate@41.173.1", "--", "renovate"]}}},
			"mise.toml": {"tools": {"npm:renovate": {"version": "41.173.1"}}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
	count(found) == 1
	some finding in found
	finding.verdict == "V-MCP-PIN-UNDECLARED"
}

# A tool name carrying an `@` keeps its head whole — the last `@` is the split.
test_a_tool_name_carrying_an_at_splits_on_the_last_one if {
	count(violation) == 0 with input as {"tree": {
		"documents": {
			".mcp.json": {"mcpServers": {"s": {"args": ["exec", "npm:@scope/pkg@1.2.3", "--", "x"]}}},
			"mise.toml": {"tools": {"npm:@scope/pkg": "1.2.3"}},
		},
		"missing": [],
	}}
		with data.batten.patterns as {"mise-tool-reference": `^[a-z0-9]+:.+@.+$`}
}
