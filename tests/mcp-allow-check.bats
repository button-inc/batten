#!/usr/bin/env bats
# The gate over MCP allow rules: a permission rule that matches no tool name is
# silent by construction, so the failure it causes (an approval prompt on every
# call) never points back at the settings file that caused it.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-allow-check"
	FIXTURE="$BATS_TEST_TMPDIR/settings.json"
	# The fourth predicate reads the session's generated MCP config, found by
	# glob when nothing says otherwise. Point every case at a path that does not
	# exist, so a fixture cannot inherit whatever is attached to the session
	# running the suite; the cases that mean to exercise it write one there.
	export BATTEN_MCP_CONFIG="$BATS_TEST_TMPDIR/mcp-config.json"
}

# Writes a settings fixture whose permissions.allow is the given JSON array.
allow() {
	printf '{"permissions":{"allow":%s,"deny":[]}}\n' "$1" >"$FIXTURE"
}

# Writes a fixture carrying an enabledMcpjsonServers value alongside the
# allowlist, for the second predicate: an enabled server with no grant.
enabled() {
	printf '{"enabledMcpjsonServers":%s,"permissions":{"allow":%s,"deny":[]}}\n' "$1" "$2" >"$FIXTURE"
}

@test "this repo's own settings pass the gate today" {
	run "$GATE" "$BATS_TEST_DIRNAME/../.claude/settings.json"
	[ "$status" -eq 0 ]
}

@test "a bare server rule with no connector companion passes — that is not this gate's claim" {
	# An earlier version demanded a `mcp__claude_ai_<server>__*` companion. The
	# exposed connector name is chosen per registration by the host (CLOUD-178),
	# so the companion is inert in a web session and the name that would help is
	# an account-specific UUID rule 1 keeps out of committed config. A gate may
	# only assert what it can verify from the repo.
	allow '["mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "both spellings present is also fine" {
	allow '["mcp__Linear", "mcp__claude_ai_Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a connector-only allowlist needs no companion of its own" {
	allow '["mcp__claude_ai_Slack__slack_send_message"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a glob in the server segment is reported, not accepted" {
	allow '["mcp__claude_ai_*__read", "mcp__claude_ai_Linear__*", "mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"server segment cannot be a glob"* ]]
}

@test "a bare unanchored allow glob is reported" {
	allow '["*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"auto-approves nothing"* ]]
}

@test "non-MCP allow rules are none of this gate's business" {
	allow '["Bash(git:*)", "Bash(mise:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "deny rules may glob freely — only allow rules are judged" {
	printf '{"permissions":{"allow":[],"deny":["mcp__*","*"]}}\n' >"$FIXTURE"
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "output is a pointer — it names rules, never settings content at large" {
	allow '["mcp__Linear"]'
	run "$GATE" "$FIXTURE"
	[[ "$output" != *'"permissions"'* ]]
}

@test "an enabled server that no allow rule names is reported" {
	# The defect this predicate exists for: serena enabled, nothing granting it,
	# so every memory read prompted and the settings file never pointed at it.
	enabled '["serena"]' '["Bash(git:*)", "mcp__Linear__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no allow rule names it"* ]]
	[[ "$output" == *"serena"* ]]
}

@test "an enabled server granted by a tool-name glob passes" {
	enabled '["serena"]' '["mcp__serena__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "an enabled server granted tool by tool passes" {
	enabled '["serena"]' '["mcp__serena__read_memory", "mcp__serena__list_memories"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a bare server-level rule grants an enabled server" {
	enabled '["serena"]' '["mcp__serena"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "every enabled server needs its own grant, not just one of them" {
	enabled '["serena", "other"]' '["mcp__serena__*"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"other"* ]]
}

@test "an absent enabledMcpjsonServers leaves the predicate nothing to say" {
	allow '["Bash(git:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "enabledMcpjsonServers set to true is not an enumerable list" {
	# The CLI accepts a boolean there; a gate may only assert what it can read.
	enabled 'true' '["Bash(git:*)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "unparseable settings exit 2, distinct from a failing allowlist" {
	printf 'not json\n' >"$FIXTURE"
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 2 ]
}

@test "a missing settings file is not a failure this gate invents" {
	run "$GATE" "$BATS_TEST_TMPDIR/absent.json"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to check"* ]]
}

# --- the third predicate: an under-matching DENY (CLOUD-178) ------------------
#
# Added after the measured defect on `d671184`: four deny rules, three of them
# naming a server the host had re-exposed under a UUID, and this gate passed them
# all because every rule was well-SHAPED. A deny that names no live tool reads as
# a prohibition and enforces nothing.

# Writes a fixture whose permissions.deny is the given JSON array.
denies() {
	printf '{"permissions":{"allow":[],"deny":%s}}\n' "$1" >"$FIXTURE"
}

@test "a deny on a host-supplied connector with no guard coverage fails" {
	denies '["mcp__Claude_Code_Remote__archive_session"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"archive_session"* ]]
	[[ "$output" == *"enforces nothing"* ]]
}

@test "a deny whose suffix a guard covers passes under any server spelling" {
	# The point of the predicate: the same verb under the readable name and under
	# a UUID are one rule as far as coverage is concerned, because the guard that
	# backs them never reads the server segment.
	denies '["mcp__Claude_Code_Remote__send_later","mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__send_later"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a deny on a server the repo itself declares needs no guard" {
	# `.mcp.json` and enabledMcpjsonServers are the repo's own declarations, so
	# those names cannot drift under it — the predicate must not demand coverage
	# it has no reason to want.
	printf '{"enabledMcpjsonServers":["serena"],"permissions":{"allow":["mcp__serena__*"],"deny":["mcp__serena__delete_memory"]}}\n' >"$FIXTURE"
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "an under-matching ALLOW is deliberately not failed" {
	# The asymmetry that scopes this predicate: an allow that matches nothing
	# fails CLOSED, into an approval prompt a human sees. Only the deny fails
	# open and silently. Asserted so a later author does not "improve" the gate by
	# symmetry and make it unlandable against every pre-existing grant.
	allow '["mcp__Claude_Code_Remote__get_session"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a non-MCP deny is not this predicate's business" {
	denies '["Bash(rm -rf *)"]'
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

# --- the fourth predicate: an allow rule naming a server that never attached ---
#
# CLOUD-684. The attached set comes from the generated MCP config, read through
# `mcp-grant-sync --attached` so the two gates share one definition of the name —
# never from the log tree, whose directory names are sanitized and lossy
# (CLOUD-665). `--config` points the reader at a fixture so these cases do not
# assert about whatever is attached to the session running them.

# A generated MCP config in the host's shape: server keys are the identifiers
# actually registered, each with the tool inventory that identifies it.
attached_config() { # attached_config <server-id> <tool>...
	local id="$1"
	shift
	local tools="[]"
	for t in "$@"; do
		tools=$(jq -c --arg t "$t" '. + [{name: $t, permission_policy: "always_ask"}]' <<<"$tools")
	done
	jq -n --arg id "$id" --argjson tools "$tools" \
		'{mcpServers: {($id): {type: "http", url: "https://api.example.invalid/mcp", headers: {authorization: "Bearer s3cr3t"}, tools: $tools}}}' >"$BATTEN_MCP_CONFIG"
}

@test "an allow rule naming a server that attached under that exact name passes" {
	allow '["mcp__github__create_pull_request"]'
	attached_config github create_pull_request
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

# THE DISCRIMINATOR (CLOUD-418, and CLOUD-684 §7b): the rule names the label, the
# session registered a generated identifier, and no projection can place it
# because a glob names no tool to identify the server by. This is the shape that
# ships today and that no existing case can express.
@test "an allow rule naming a label while the session registered an identifier is inert" {
	allow '["mcp__Linear__*"]'
	attached_config 4db58e41-cd4e-4818-8922-46cf616593f4 get_issue save_issue
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Linear"* ]]
	[[ "$output" == *"grants nothing"* ]]
}

# The same label, one literal tool named beside the glob: now the projection can
# identify the server by a tool name, so the grant is carried onto the live
# identifier and the rule is not inert. This is the closable half — without it
# the predicate would be a verdict no edit could ever satisfy, since a committed
# rule cannot name an identifier that rotates.
@test "a label the projection can place is not inert" {
	allow '["mcp__Linear__*","mcp__Linear__get_issue"]'
	attached_config 4db58e41-cd4e-4818-8922-46cf616593f4 get_issue save_issue
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a declared server is never judged inert — its name is the repo's own" {
	enabled '["serena"]' '["mcp__serena__*"]'
	attached_config 4db58e41-cd4e-4818-8922-46cf616593f4 get_issue
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "the inert finding carries no tool name, URL or header value" {
	allow '["mcp__Linear__*"]'
	attached_config 4db58e41-cd4e-4818-8922-46cf616593f4 get_issue save_issue
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"get_issue"* ]]
	[[ "$output" != *"save_issue"* ]]
	[[ "$output" != *"http"* ]]
	[[ "$output" != *"s3cr3t"* ]]
}

# Six rules naming one dead label are one thing to fix, not six.
@test "one finding per label, not per rule" {
	allow '["mcp__Gone__alpha","mcp__Gone__beta","mcp__Gone__gamma"]'
	attached_config 4db58e41-cd4e-4818-8922-46cf616593f4 get_issue
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[ "$(grep -c -- 'Gone' <<<"$output")" = "1" ]
}

# FAILS OPEN where it cannot look. An attached-server set is a property of the
# world, and CI has no MCP session — a gate that reported inert there would fail
# every rule in the file for a reason that is not about the commit.
@test "no generated config means no verdict — the predicate is skipped, not assumed" {
	allow '["mcp__Linear__*"]'
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

# The existing predicate is untouched by the new one: an enabled server with no
# grant is still that finding, not an inert-rule finding.
@test "an enabled server with no grant keeps its own verdict" {
	enabled '["serena"]' '["mcp__github__create_pull_request"]'
	attached_config github create_pull_request
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"every call to it prompts"* ]]
}
