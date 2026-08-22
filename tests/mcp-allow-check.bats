#!/usr/bin/env bats
# subject: mise-tasks/mcp-allow-check.sh
# The gate over MCP allow rules: a permission rule that matches no tool name is
# silent by construction, so the failure it causes (an approval prompt on every
# call) never points back at the settings file that caused it.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-allow-check.sh"
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

# --- the fourth predicate: an allow rule the connector control cannot honour ---
#
# CLOUD-765, replacing CLOUD-684's predicate. That one reported a rule naming a
# server not attached under that name, which `connector-allow-guard` (CLOUD-191)
# repairs per call — so the finding was false wherever the guard is wired. This
# reports the one no translation repairs: a tool the connector sets to `ask`,
# which no allow rule at any scope skips.
#
# The fixtures carry the `mcp_url` endpoint `connector-allow-resolve` anchors on,
# because that resolver — not this suite, and not a second copy of it — is what
# says which committed alias a live key means. `BATTEN_MCP_CONFIG` keeps every
# case off whatever is attached to the session running it.

TOOLBOX_ENDPOINT_ENC="https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta"

# A generated config in the host's shape: a rotating key, the toolbox endpoint
# behind it, and a per-tool control the host wrote.
policy_config() { # policy_config <server-id> <tool>:<policy>...
	local id="$1"
	shift
	local tools="[]"
	for pair in "$@"; do
		tools=$(jq -c --arg t "${pair%%:*}" --arg p "${pair##*:}" \
			'. + [{name: $t, permission_policy: $p}]' <<<"$tools")
	done
	jq -n --arg id "$id" --arg u "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=$TOOLBOX_ENDPOINT_ENC" --argjson tools "$tools" \
		'{mcpServers: {($id): {type: "http", url: $u, headers: {authorization: "Bearer s3cr3t"}, tools: $tools}}}' >"$BATTEN_MCP_CONFIG"
}

@test "an allow rule whose tool the connector allows passes" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_allow
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

# THE DISCRIMINATOR (CLOUD-418, and CLOUD-765 §7b). The rule is well-formed, the
# alias is the committed one, the server is attached — and the connector sets the
# tool to `ask`, so the rule cannot do what it says. No earlier case can express
# this, and `mise run mutant` drives it red through `allow-check-ignores-policy`.
@test "an allow rule whose tool the connector sets to ask is unenforceable" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"always_ask"* ]]
	# The remedy is named, because an agent told only "this does not work"
	# reaches for the file it can write.
	[[ "$output" == *"Tool permissions"* ]]
}

# A deny at the same policy is ENFORCED — the control chooses ask versus allow and
# never widens a deny. Reporting it would say "delete the rules doing the only
# enforcement there is".
@test "a deny on the same tool is never reported" {
	printf '{"permissions":{"allow":[],"deny":["mcp__Claude_Code_Remote__send_later"]}}\n' >"$FIXTURE"
	policy_config cccccccc-1111-2222-3333-444444444444 send_later:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "a tool no rule names is not reported, whatever its policy" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_allow create_session:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

# A claude.ai connector is authorised at the connector layer, so the resolver
# answers `-` for it and this predicate has nothing to say — translating its name
# would be granting what the committed file does not.
@test "a server that is not the toolbox is left alone" {
	allow '["mcp__Linear__list_issues"]'
	jq -n '{mcpServers: {"dddddddd-9999-8888-7777-666666666666": {url: "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp", tools: [{name: "list_issues", permission_policy: "always_ask"}]}}}' >"$BATTEN_MCP_CONFIG"
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "the finding carries no tool name, URL or header value" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"list_sessions"* ]]
	[[ "$output" != *"s3cr3t"* ]]
	[[ "$output" != *"api.anthropic.com"* ]]
}

# Six rules against one connector setting are one thing to fix.
@test "one finding per alias, with a count" {
	allow '["mcp__Claude_Code_Remote__list_sessions","mcp__Claude_Code_Remote__get_session","mcp__Claude_Code_Remote__create_session"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_ask get_session:always_ask create_session:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[ "$(grep -c -- 'Claude_Code_Remote' <<<"$output")" = "1" ]
	[[ "$output" == *"3 allow rule(s)"* ]]
}

# FAILS OPEN where it cannot look. A connector control is a property of the world,
# and CI has no MCP session.
@test "no generated config means no verdict — the predicate is skipped, not assumed" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

# The commit-scoped half never consults the world: without --session the same
# unenforceable rule is silent, which is what keeps this out of the hk gate.
@test "without --session the connector control is not consulted" {
	allow '["mcp__Claude_Code_Remote__list_sessions"]'
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_ask
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "an enabled server with no grant keeps its own verdict" {
	enabled '["serena"]' '["mcp__github__create_pull_request"]'
	policy_config cccccccc-1111-2222-3333-444444444444 create_pull_request:always_allow
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"every call to it prompts"* ]]
}

# --- a GUARD ALLOW ARM the connector cannot honour (CLOUD-790) ----------------
#
# WHY THE PREDICATE ABOVE COULD NOT COVER THIS, which is the finding rather than a
# scoping note. It judges allow RULES, resolved through `connector-allow-resolve`,
# which answers only for the toolbox alias. Measured 2026-08-20:
# `unsubscribe_pr_activity` was `always_ask` on the live connector and prompted on
# every landing, no rule in the committed file named it under that alias, and the
# gate passed throughout. What claimed the pre-approval was a HOOK'S ALLOW ARM —
# `hookSpecificOutput.permissionDecision: "allow"` — which is not a rule and is
# invisible to a rule-shaped check.
#
# The fixture supplies its own guard directory, because in this repository the arm
# is now empty (that is the fixed state) and a row reading the real guards would
# exercise nothing.

# A stand-in guard publishing one pre-approved suffix, in the `--covers-allow`
# shape `connector-verb-guard` defines.
guard_dir() { # guard_dir <suffix>...
	GUARDS="$BATS_TEST_TMPDIR/guards"
	mkdir -p "$GUARDS"
	{
		printf '%s\n' '#!/usr/bin/env bash'
		printf '%s\n' '[ "${1:-}" = "--covers-allow" ] || exit 0'
		for suffix in "$@"; do printf 'printf %s\\\\n %s\n' "'%s'" "$suffix"; done
	} >"$GUARDS/fixture-guard.sh"
	chmod +x "$GUARDS/fixture-guard.sh"
	export BATTEN_GUARD_DIR="$GUARDS"
}

@test "CLOUD-790: a pre-approved suffix the connector sets to ask is refused" {
	# THE DISCRIMINATOR. No allow rule names this tool anywhere — the whole point
	# is that a hook, not a rule, made the claim.
	allow '[]'
	guard_dir unsubscribe_pr_activity
	policy_config cccccccc-1111-2222-3333-444444444444 unsubscribe_pr_activity:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unsubscribe_pr_activity"* ]]
	[[ "$output" == *"always_ask"* ]]
	# The remedy is named, and it is not an edit to this repository.
	[[ "$output" == *"Tool permissions"* ]]
}

@test "CLOUD-790: a pre-approved suffix the connector allows is silent" {
	allow '[]'
	guard_dir unsubscribe_pr_activity
	policy_config cccccccc-1111-2222-3333-444444444444 unsubscribe_pr_activity:always_allow
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "CLOUD-790: a suffix on a server that is NOT the toolbox is judged too" {
	# Unlike the rule predicate, this one spans every attached server: a hook
	# decides by tool-name suffix and therefore has no server to be scoped to.
	# Scoping it to the toolbox would rebuild the blindness it exists to fix.
	allow '[]'
	guard_dir list_issues
	jq -n '{mcpServers: {"dddddddd-9999-8888-7777-666666666666": {url: "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp", tools: [{name: "list_issues", permission_policy: "always_ask"}]}}}' >"$BATTEN_MCP_CONFIG"
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"list_issues"* ]]
}

@test "CLOUD-790: a suffix the live config does not expose is not reported" {
	# Absent is not `ask`. A verb the host is not serving this session says
	# nothing about whether a hook could pre-approve it, and guessing would make
	# the gate red for a reason no one can act on.
	allow '[]'
	guard_dir unsubscribe_pr_activity
	policy_config cccccccc-1111-2222-3333-444444444444 list_sessions:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "CLOUD-790: no pre-approved suffix at all is a PASS, not an error" {
	# This repository's own state after the arm was removed. It must produce the
	# summary line rather than dying on an empty match — the fail-shaped-as-pass
	# that a `grep` with no hits caused under `set -e` while this was being built.
	allow '[]'
	GUARDS="$BATS_TEST_TMPDIR/empty-guards"
	mkdir -p "$GUARDS"
	export BATTEN_GUARD_DIR="$GUARDS"
	policy_config cccccccc-1111-2222-3333-444444444444 unsubscribe_pr_activity:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
	[ -z "$output" ] # silence is the pass (CLOUD-891)
}

@test "CLOUD-790: without --session the guard arm is not judged" {
	allow '[]'
	guard_dir unsubscribe_pr_activity
	policy_config cccccccc-1111-2222-3333-444444444444 unsubscribe_pr_activity:always_ask
	run "$GATE" "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "CLOUD-790: no generated config means no verdict on the arm" {
	allow '[]'
	guard_dir unsubscribe_pr_activity
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 0 ]
}

@test "CLOUD-790: the finding is a pointer — no server key or URL" {
	allow '[]'
	guard_dir unsubscribe_pr_activity
	policy_config cccccccc-1111-2222-3333-444444444444 unsubscribe_pr_activity:always_ask
	run "$GATE" --session "$FIXTURE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"cccccccc"* ]]
	[[ "$output" != *"http"* ]]
	[[ "$output" != *"s3cr3t"* ]]
}
