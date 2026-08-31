# METADATA
# description: |
#   CLOUD-1247. The COMMITTED half of the harness grant, and deliberately a
#   different subject from `harness-wiring`: that module reads
#   `input.tree.external["harness-settings"]`, the MERGED wiring assembled under
#   the user's own home directory, and decides which mediator runs. This one
#   reads the repository's own `.claude/settings.json` and decides whether the
#   grant this repository ships is still there. Two authorities, two modules; a
#   reader who conflates them will look for this predicate in the wrong file.
#
#   WHY A GATE AT ALL, rather than a comment in the settings file. Measured
#   2026-08-31: `permissions.allow` had carried `Bash(batten:*)` since the file
#   existed and it granted NOTHING, because the auto-mode classifier is a second
#   layer that does not consult the allowlist. Every bare `batten` invocation was
#   refused for most of a session -- `batten --version` included -- in the
#   repository whose own product `batten` is. That is CLOUD-765's class: a
#   committed allow rule that cannot take effect, and nothing saying so.
#
#   THE SENTINEL IS THE LOAD-BEARING CONJUNCT and is not decoration. `$defaults`
#   inherits the built-in classifier rules at its position. A tree that keeps the
#   batten clause and drops the sentinel looks correct to a reader and to any
#   predicate that only greps for `batten`, while having silently discarded every
#   built-in safety rule -- strictly worse than having neither. So it is refused
#   in its own right, with its own class, rather than folded into the first.
#
#   WHAT THIS DOES NOT DO: it does not assert the grant WORKS. Whether the host
#   honours `autoMode` from project settings is the host's behaviour, unreadable
#   from here, and a gate claiming otherwise would be the "authority it does not
#   hold" defect one level up. It asserts only that the committed file still says
#   what CLOUD-1247 landed. The working half is pinned by that row's acceptance,
#   run against a real host.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.harness_grant

import rego.v1

rules contains "harness-grant"

# The settings file's auto-mode allow list, or nothing.
#
# ABSENT IS NOT EMPTY. A tree whose `.claude/settings.json` will not parse, or
# which carries no `autoMode` at all, leaves this undefined, every rule below
# silent, and the could-not-look finding to `input.tree.missing`, which the
# engine owns. A module that manufactured an empty list here would report the
# grant missing on a tree it was never able to read.
grants := entries if {
	entries := input.tree.documents[".claude/settings.json"].autoMode.allow
	is_array(entries)
}

# The sentinel that inherits the built-in classifier rules at its position.
sentinel := "$defaults"

# The program the grant has to name for this repository to be usable at all.
mediator := "batten"

names_the_mediator if {
	some entry in grants
	contains(entry, mediator)
}

keeps_the_defaults if {
	some entry in grants
	entry == sentinel
}

# The grant is gone, so this repository's own binary is refused by the layer that
# actually decides.
violation contains {
	"rule": "harness-grant",
	"verdict": "V-HARNESS-GRANT-ABSENT",
	"subjects": [{"path": ".claude/settings.json"}],
} if {
	grants
	not names_the_mediator
}

# The grant is present and every built-in safety rule was discarded with it.
violation contains {
	"rule": "harness-grant",
	"verdict": "V-HARNESS-GRANT-DEFAULTS-DROPPED",
	"subjects": [{"path": ".claude/settings.json"}],
} if {
	grants
	not keeps_the_defaults
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.documents` for a DOTFILE path at all -- a `with input as` case
# fabricates the very shape the engine may be unable to produce -- which is why
# `crates/batten/tests/harness_grant.rs` exists over the compiled binary. That is
# the tier `.claude/rules/policy-modules.md` records both live instances of the
# dead-gate class as having been found by adding.

settings(entries) := {"tree": {"documents": {".claude/settings.json": {"autoMode": {"allow": entries}}}}}

test_the_landed_shape_is_clean if {
	count(violation) == 0 with input as settings(["$defaults", "Allow every `batten` subcommand."])
}

test_a_dropped_grant_is_refused if {
	some v in violation with input as settings(["$defaults"])
	v.verdict == "V-HARNESS-GRANT-ABSENT"
}

# The anti-vacuity mirror. Without it the clean case above is satisfied by a
# predicate that only ever looks for `batten`, and the sentinel guarantee ships
# as coverage having never been walked.
test_a_dropped_sentinel_is_refused if {
	some v in violation with input as settings(["Allow every `batten` subcommand."])
	v.verdict == "V-HARNESS-GRANT-DEFAULTS-DROPPED"
}

test_both_missing_raises_both if {
	count(violation) == 2 with input as settings([])
}

# COULD NOT LOOK IS NOT A REFUSAL, and this is the case that keeps the module
# from reading a tree it never parsed as a tree carrying no grant.
test_no_automode_block_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {".claude/settings.json": {"permissions": {"allow": []}}}}}
}

test_no_settings_file_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

#MUTANT-EXEMPT CLOUD-1247|no `tests/harness-grant.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `V-SHELL-RULE-ADDED` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/harness_grant.rs`, neither of which is what the mutation runner drives
