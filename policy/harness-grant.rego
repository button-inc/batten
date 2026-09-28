# METADATA
# description: |
#   CLOUD-1379, inverting CLOUD-1247. The committed half of the harness grant,
#   and deliberately a different subject from `harness-wiring`: that module reads
#   `input.tree.external["harness-settings"]`, the MERGED wiring assembled under
#   the user's own home directory, and decides which mediator runs. This one
#   reads the repository's own `.claude/settings.json`. Two authorities, two
#   modules; a reader who conflates them will look for this predicate in the
#   wrong file.
#
#   WHAT IT REFUSES: an `autoMode` block in the COMMITTED settings file. The
#   primary doc says so outright — "The classifier doesn't read `autoMode` from
#   project settings in `.claude/settings.json` or `.claude/settings.local.json`.
#   Both files live in the repo directory, so a checked-in repo or a build step
#   could otherwise inject its own allow rules"
#   (https://code.claude.com/docs/en/auto-mode-config). It reads
#   `~/.claude/settings.json`, managed settings and `--settings`, and nothing
#   else.
#
#   WHY THE INVERSION, measured rather than argued. This module used to REQUIRE
#   that block — the mediator named, `$defaults` kept, a read-only clause — so
#   every classifier refusal was answered by adding prose to a file the
#   classifier never opens, and the gate held the answer in place. By
#   2026-09-28 the block was 22 entries and ~13k characters, one clause added
#   that day, with the identical refusals still arriving. That is CLOUD-765's
#   class — a committed grant that cannot take effect, with nothing saying so —
#   and the gate built to prevent it was the thing keeping it alive.
#
#   WHAT THIS DOES NOT DO: it does not assert that a grant exists where the
#   classifier does read one. Those scopes are a developer's home, an
#   organisation's managed settings, or a launcher's `--settings`; none is the
#   repository's to write, and writing one from the repository is the injection
#   the doc sentence above exists to prevent. The committed lever the classifier
#   DOES read is CLAUDE.md, which it loads as Claude does.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.harness_grant

import rego.v1

rules contains "grant carry missing"

# The inert block: any `autoMode` key at all, whatever it holds. An empty one is
# refused too, because it reads to the next author as the place a grant goes.
#
# THE DOCUMENT IS READ INLINE AND NEVER BOUND AS A RULE, and that is load-bearing.
# The engine collects `deny`, `violation` and `rules` members at ANY depth under
# `data.batten` (`policy.rs`, `collect_strings`), so a rule whose value is the
# settings document hands the engine its `permissions.deny` array as bare deny
# tokens. Measured: six findings, one per denied tool, on a file with no
# `autoMode` at all.
#
# ABSENT IS NOT CLEAN AND NOT A REFUSAL. A tree whose `.claude/settings.json`
# will not parse leaves the body undefined; the could-not-look finding is
# `input.tree.missing`'s, which the engine owns.
violation contains {
	"rule": "grant carry missing",
	"verdict": "grant carry missing",
	"subjects": [{"path": ".claude/settings.json"}],
} if {
	document := input.tree.documents[".claude/settings.json"]
	is_object(document)
	"autoMode" in object.keys(document)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.documents` for a DOTFILE path at all -- a `with input as` case
# fabricates the very shape the engine may be unable to produce -- which is why
# `crates/batten/tests/it/harness_grant.rs` exists over the compiled binary.

on_disk(document) := {"tree": {"documents": {".claude/settings.json": document}}}

test_a_committed_grant_is_refused if {
	some v in violation with input as on_disk({"autoMode": {"allow": ["$defaults", "batten"]}})
	v.verdict == "grant carry missing"
}

test_an_empty_committed_block_is_refused if {
	some v in violation with input as on_disk({"autoMode": {}})
	v.verdict == "grant carry missing"
}

# The anti-vacuity mirror: without it, a predicate refusing every settings file
# passes both cases above.
test_settings_without_the_block_are_clean if {
	count(violation) == 0 with input as on_disk({"permissions": {"allow": ["Bash(batten:*)"]}})
}

# COULD NOT LOOK IS NOT A REFUSAL.
test_no_settings_file_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

#MUTANT-SUITE crates/batten/tests/it/harness_grant.rs
#MUTANT grant-unread|s@^\t"autoMode" in object.keys\(document\)$@\tfalse@|a_committed_grant_is_refused
