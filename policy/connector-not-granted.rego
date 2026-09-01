# METADATA
# description: |
#   CLOUD-1260. Closing the raw path, as a gate rather than as a convention.
#
#   Dispatch and config resolution save NOTHING while a cheaper-looking route to
#   the full payload sits in the model's tool list. An earlier draft of the row
#   rested that on "the convention of calling `batten`" — and a convention is
#   prose with no gate, which non-negotiable rule 2 calls feedforward only. It is
#   also falsified by the measurement the row was written from: the raw tools
#   WERE registered, and one session therefore called them 973 times, for 13.2 MB
#   and 73% of all its tool output.
#
#   So the predicate: a tool this repository has declared a `[[mcp.result]]`
#   reduction for must not ALSO be granted raw in the settings this repository
#   commits. Granting both is not a fallback, it is the reduction not applying —
#   the two routes return the same payload and the cheaper-looking one wins every
#   time.
#
#   WHAT THIS DOES AND DOES NOT REACH, stated rather than left to be discovered.
#   The row's design (b) is that the connector is not REGISTERED for the session
#   at all, so there is nothing left to intercept and the invariant holds by
#   construction on every harness. Registration happens where the launcher writes
#   its wiring, which is outside this repository and outside every gate here —
#   the same shape `.claude/rules/commits.md` records for the user-level identity
#   hook. What this repository OWNS is whether its own committed settings hand the
#   raw tools back, and that is exactly what is asserted. A gate claiming to
#   assert registration would be the "authority it does not hold" defect, and
#   `harness-grant` records the same boundary for its own subject one file over.
#
#   THE TOOL NAMES ARE THIS REPOSITORY'S, and they live here rather than in
#   `crates/batten` for non-negotiable rule 1's reason — a consumer module is the
#   home for a predicate naming a consumer's facts. They are string literals
#   rather than a `[[pattern]]` row because this is a prefix comparison and not a
#   regex; an inline expression would be refused at load, and rightly.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.connector_not_granted

import rego.v1

rules contains "connector-not-granted"

# The settings file's permission allow list, or nothing.
#
# ABSENT IS NOT EMPTY, which is `harness-grant`'s discipline and the reason this
# module cannot report a clean tree it never read: a settings file that will not
# parse, or one carrying no `permissions` block, leaves this undefined, every rule
# below silent, and the could-not-look finding to `input.tree.missing`, which the
# engine owns.
allows := entries if {
	entries := input.tree.documents[".claude/settings.json"].permissions.allow
	is_array(entries)
}

# The connector whose responses `[[mcp.result]]` reduces, as the host names its
# tools: `mcp__<server>__<tool>`. A prefix, so a grant naming one tool and a grant
# globbing the whole server are the same finding — they are, because either one
# puts the unreduced payload back on the model's surface.
reduced_connector := "mcp__Linear"

granted contains entry if {
	some entry in allows
	startswith(entry, reduced_connector)
}

# The reduction is declared and the raw route is granted beside it, so the
# reduction decides nothing.
#
# POINTER-ONLY: the settings path and a COUNT of offending entries. Never the
# entries themselves — a finding that listed them would be restating the grant it
# refuses, and rule 4's subject vocabulary has a `count` for exactly this.
violation contains {
	"rule": "connector-not-granted",
	"verdict": "connector grant loose",
	"subjects": [{"path": ".claude/settings.json"}, {"count": count(granted)}],
} if {
	allows
	count(granted) > 0
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.documents` for this path, or that it distinguishes an unparseable
# settings file from one carrying no grant — a `with input as` case fabricates the
# very shape the engine may be unable to produce. That is
# `crates/batten/tests/connector_not_granted.rs`, over the compiled binary.

settings(entries) := {"tree": {"documents": {".claude/settings.json": {"permissions": {"allow": entries}}}}}

test_a_tree_granting_nothing_raw_is_clean if {
	count(violation) == 0 with input as settings(["Bash(git:*)", "mcp__serena__*"])
}

test_a_named_raw_tool_is_refused if {
	some v in violation with input as settings(["mcp__Linear__get_issue"])
	v.verdict == "connector grant loose"
}

# THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by a predicate
# matching only that one exact string, and a wildcard grant — which is strictly
# wider — would ship past the gate that exists to refuse it.
test_a_globbed_server_grant_is_refused if {
	some v in violation with input as settings(["mcp__Linear__*"])
	v.verdict == "connector grant loose"
}

test_a_bare_server_grant_is_refused if {
	some v in violation with input as settings(["mcp__Linear"])
	v.verdict == "connector grant loose"
}

# The finding is ONE per file however many entries offend, carrying a count. A
# rule emitting one finding per entry would restate the grant in the report,
# which is the payload-in-the-finding shape rule 4 refuses.
test_many_grants_are_one_finding_carrying_a_count if {
	count(violation) == 1 with input as settings(["mcp__Linear", "mcp__Linear__*", "mcp__Linear__get_issue"])
	some v in violation with input as settings(["mcp__Linear", "mcp__Linear__*", "mcp__Linear__get_issue"])
	some s in v.subjects
	s.count == 3
}

# COULD NOT LOOK IS NOT A REFUSAL, and it is not a pass either: the engine's own
# `missing` channel carries it, and this module stays silent rather than reporting
# a tree it never read as a tree with no grant.
test_no_permissions_block_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {".claude/settings.json": {"autoMode": {"allow": []}}}}}
}

test_no_settings_file_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

#MUTANT-EXEMPT CLOUD-1260|no `tests/connector-not-granted.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `shell add refused` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/connector_not_granted.rs`, neither of which is what the mutation runner drives
