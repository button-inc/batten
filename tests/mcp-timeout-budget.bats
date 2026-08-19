#!/usr/bin/env bats
# CLOUD-668. The MCP startup budget is declared and measured, never the host
# default.
#
# The rows are written so that a gate checking only PRESENCE passes the exact
# state the issue was filed about: the host default of 30000 is a declared
# value, and it is the value that lost Serena twice in one session. That is the
# `#MUTANT` this suite is proven against, and it is why `refuses the host
# default` is the load-bearing case rather than `refuses an absent key`.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mcp-timeout-budget"
	S="$BATS_TEST_TMPDIR/settings.json"
	LOGS="$BATS_TEST_TMPDIR/logs"
}

declare_timeout() { # declare_timeout <value>
	jq -n --arg v "$1" '{env: {MCP_TIMEOUT: $v}, hooks: {}}' >"$S"
}

# A settings file that also enables a server, so the effect half has something
# to look for. The declaration half ignores this key entirely, which is why the
# rows above can keep using the simpler writer.
declare_with_server() { # declare_with_server <value> <server>
	jq -n --arg v "$1" --arg s "$2" \
		'{env: {MCP_TIMEOUT: $v}, enabledMcpjsonServers: [$s], hooks: {}}' >"$S"
}

# One connection log, named the way the CLI names them: the UTC start instant,
# whose lexicographic order is its chronological one.
log_connection() { # log_connection <server> <observed-ms> [stamp]
	local dir="$LOGS/mcp-logs-$1" stamp="${3:-2026-08-19T14-28-33-648Z}"
	mkdir -p "$dir"
	printf '{"debug":"Starting connection with timeout of %sms"}\n' "$2" >"$dir/$stamp.jsonl"
}

@test "the committed budget passes" {
	run "$GATE" --settings "$BATS_TEST_DIRNAME/../.claude/settings.json"
	[ "$status" -eq 0 ]
	[[ "$output" == *"at or above the measured floor"* ]]
}

@test "a value below the floor is refused, and both numbers are named" {
	declare_timeout 30000
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"30000"* ]]
	[[ "$output" == *"105494"* ]]
}

@test "exactly the floor passes — the bound is inclusive" {
	declare_timeout 105494
	run "$GATE" --settings "$S"
	[ "$status" -eq 0 ]
}

@test "one millisecond under the floor is refused" {
	declare_timeout 105493
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
}

@test "an absent key is refused — the host default is not a measured budget" {
	jq -n '{hooks: {}}' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"host default"* ]]
}

@test "a non-numeric value is refused rather than compared" {
	declare_timeout "2 minutes"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"whole number of milliseconds"* ]]
}

@test "an unreadable settings file is exit 2, never a silent pass" {
	run "$GATE" --settings "$BATS_TEST_TMPDIR/absent.json"
	[ "$status" -eq 2 ]
}

@test "settings that are not JSON are exit 2, never a silent pass" {
	printf 'not json\n' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 2 ]
}

# Pointer-only (non-negotiable 4): the two numbers, never the settings body.
@test "the refusal echoes no other settings content" {
	jq -n '{env: {MCP_TIMEOUT: "30000", SECRET_TOKEN: "tok-must-not-appear"}}' >"$S"
	run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" != *"tok-must-not-appear"* ]]
	[[ "$output" != *"SECRET_TOKEN"* ]]
}

# THE HANG. `shift 2` on a single remaining argument shifts nothing and returns
# non-zero, and this gate runs without `errexit` — so `--settings` with no value
# spun the argument loop forever. `timeout` is the assertion: a gate that hangs
# never reports, and both `verify` and the hk gate wait on this one. Caught in
# review on PR #489.
@test "--settings with no value is refused, and does not hang" {
	run timeout 10s "$GATE" --settings
	[ "$status" -eq 2 ]
	[[ "$output" == *"needs a file"* ]]
}

@test "--settings with an empty value is refused rather than silently defaulted" {
	run timeout 10s "$GATE" --settings ""
	[ "$status" -eq 2 ]
}

# --- the effect half (CLOUD-700) ---------------------------------------------
#
# The declaration passed for ten sessions while the client used the host default,
# so these rows are the ones that decide whether this gate measures anything. The
# `declaration-without-effect` mutation removes exactly this half.

@test "a budget the client actually used passes, and says it is in force" {
	declare_with_server 120000 serena
	log_connection serena 120000
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 0 ]
	[[ "$output" == *"in force"* ]]
}

@test "an observed budget below the declared one is refused" {
	# THE CASE THAT WAS SILENT: declared high, client used the host default.
	# Recorded sessions looked exactly like this and nothing fired, because the
	# only check was over the settings file.
	declare_with_server 120000 serena
	log_connection serena 30000
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"30000"* ]]
	[[ "$output" == *"120000"* ]]
	[[ "$output" == *"host ignored"* ]]
}

@test "the refusal names both numbers and no log line" {
	declare_with_server 120000 serena
	local dir="$LOGS/mcp-logs-serena"
	mkdir -p "$dir"
	printf '{"debug":"Starting connection with timeout of 30000ms"}\n{"debug":"Server stderr: SENTINEL-9f3a"}\n' \
		>"$dir/2026-08-19T14-28-33-648Z.jsonl"
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" != *"SENTINEL"* ]]
}

@test "an absent log tree is not a live session, so the declaration is all there is" {
	declare_with_server 120000 serena
	run "$GATE" --settings "$S" --logs "$BATS_TEST_TMPDIR/nowhere"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not a live session"* ]]
}

@test "a live tree whose log records no budget is exit 2, never a pass" {
	declare_with_server 120000 serena
	local dir="$LOGS/mcp-logs-serena"
	mkdir -p "$dir"
	printf '{"debug":"something else entirely"}\n' >"$dir/2026-08-19T14-28-33-648Z.jsonl"
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 2 ]
}

@test "the NEWEST log decides, so a stale passing attempt cannot vouch for this one" {
	declare_with_server 120000 serena
	log_connection serena 120000 2026-08-19T09-00-00-000Z
	log_connection serena 30000 2026-08-19T14-28-33-648Z
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 1 ]
	[[ "$output" == *"30000"* ]]
}

@test "a server enabled but never logged is not judged — absence is not a low budget" {
	declare_with_server 120000 serena
	mkdir -p "$LOGS"
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "an observed budget ABOVE the declared one is not a refusal" {
	# The comparison is one-sided on purpose: the declaration is a floor on what
	# the client must allow, not a ceiling on what the host may be generous with.
	declare_with_server 120000 serena
	log_connection serena 300000
	run "$GATE" --settings "$S" --logs "$LOGS"
	[ "$status" -eq 0 ]
}

@test "--logs with no value is refused, and does not hang" {
	declare_timeout 120000
	run "$GATE" --settings "$S" --logs
	[ "$status" -eq 2 ]
}

# --- the floor carries its own arithmetic (CLOUD-730) ------------------------
#
# `timeout-check` refuses a workflow budget whose declared minutes disagree with
# its own stated p95 x multiplier. These rows are that failure class for the one
# budget its glob does not cover, and they exist because the drift already
# happened: the floor moved 60000 -> 105494 on a re-measured worst success of
# 52747 ms while the header went on justifying it with the superseded 16.65s.
#
# The gate parses the FLOOR line out of `$MCP_TIMEOUT_BUDGET`, defaulting to its
# own file, so a fixture can declare every direction. The floor the parse yields
# is the floor enforced — the number and its basis cannot be varied apart.

budget_file() { # budget_file <FLOOR line>
	local f="$BATS_TEST_TMPDIR/budget.sh"
	printf '%s\n' "$1" >"$f"
	printf '%s' "$f"
}

@test "a floor equal to its declared basis passes" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=105494 # budget: worst=52747ms x2 measured=2026-08-19')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 0 ]
}

@test "a floor raised without moving its basis is refused, and both numbers are named" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=200000 # budget: worst=52747ms x2 measured=2026-08-19')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"200000"* ]]
	[[ "$output" == *"105494"* ]]
	[[ "$output" == *"disagrees with the basis"* ]]
}

@test "a basis moved without the floor is refused — drift in either direction" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=105494 # budget: worst=90000ms x2 measured=2026-08-19')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"disagrees with the basis"* ]]
}

@test "a floor with no budget comment is refused — a limit with no measurement" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=105494')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no parsable budget comment"* ]]
}

@test "a malformed budget comment is refused rather than parsed loosely" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=105494 # budget: about twice the worst one')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no parsable budget comment"* ]]
}

@test "a budget comment with no measurement date is refused" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=105494 # budget: worst=52747ms x2')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no parsable budget comment"* ]]
}

@test "an unreadable budget file is exit 2, never a silent pass" {
	declare_timeout 120000
	MCP_TIMEOUT_BUDGET="$BATS_TEST_TMPDIR/absent-budget.sh" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 2 ]
}

# The arithmetic is checked BEFORE the declaration is compared, so a repo whose
# floor has drifted cannot report a green budget on the strength of it.
@test "the arithmetic is refused even when the declared budget clears the floor" {
	declare_timeout 999999
	MCP_TIMEOUT_BUDGET="$(budget_file 'FLOOR=1 # budget: worst=52747ms x2 measured=2026-08-19')" \
		run "$GATE" --settings "$S"
	[ "$status" -eq 1 ]
}
