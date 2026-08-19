#!/usr/bin/env bash
#MISE description="Gate: every server this repo enables actually ATTACHED this session — reads the CLI's own MCP connection logs, pointer-only"
#
# CLOUD-316. `mcp-allow-check` gates that an enabled server has a grant; nothing
# gated that an enabled server CONNECTED. That gap is the whole defect: Serena
# was declared, enabled, granted, pinned and startable, and absent for an entire
# session, because the launch failed and nothing read the record of it. The CLI
# writes that record and no gate opened the file — sensor without a gate, which
# non-negotiable rule 2 exists to forbid.
#
# Measured on this repo, 2026-08-11, both shapes from the same session:
#
#   {"debug":"Connection failed after 30019ms (CONNECT_TIMEOUT): MCP server
#     \"serena\" connection timed out after 30000ms", …}
#   {"debug":"Successfully connected (transport: stdio) in 12495ms", …}
#
# TWO THINGS THAT LOOK LIKE THE SIGNATURE AND ARE NOT. Both were believed here
# before being measured, so they are named rather than left to be rediscovered:
#
#   * The failure code is NOT fixed at `-32000`. CLOUD-316 was written from a
#     `-32000: Connection closed` (an exec that died), and the very next
#     occurrence was `CONNECT_TIMEOUT` (an exec too slow to finish). Both are
#     "did not attach". Keying on the literal code would have passed the second
#     one green, so the predicate is the `Connection failed` record and the code
#     is only carried into the report.
#   * An `error` KEY does not mean an error. The server's stdout/stderr is
#     tee'd into records shaped `{"error":"Server stderr: INFO … Starting Serena
#     server (version=1.6.1…)"}` — routine startup chatter on a healthy launch.
#     A gate that fired on `has("error")` would fail every green session.
#
# So the question is the LAST connection outcome in the newest log, and nothing
# else: a failure followed by a successful reconnect is a session that has its
# server.
#
# WHY IT IS NOT IN THE hk GATE. This reads session state — logs written by the
# harness, outside the repo — so it is a property of the WORLD, not of the
# commit (see .claude/rules/toolchain.md, "which of the two it is"). CI has no
# MCP session and would be asserting nothing. It runs on `UserPromptSubmit`, the
# first event after MCP startup, so a lost server is reported in the session's
# first turn rather than discovered three tasks in — CLOUD-261's principle
# applied to a server instead of a container. Its LOGIC is still gated: the
# suite drives it over fixture log trees, the split `gh-guard`/`gh-guard-check`
# already uses.
#
# Output is pointer-only per non-negotiable rule 4: the server name and the
# failure code. Never a log line — these carry the server's stderr, which is
# arbitrary content this repo does not control.
#
# THE LOG TREE CANNOT ANSWER "IS THIS PERMISSION RULE'S SERVER NAME RIGHT?", and
# this note exists because a session convinced itself otherwise and shipped it
# (CLOUD-665, reverted the same day).
#
# `mcp-logs-<server>` SANITIZES: every non-alphanumeric run in the server name
# becomes a hyphen. The connectors prove it — `Apollo.io` logs as
# `mcp-logs-Apollo-io`, `Google Drive` as `mcp-logs-Google-Drive`, `Microsoft
# 365` as `mcp-logs-Microsoft-365` — and no directory in the tree contains an
# underscore at all. The transform is lossy and not invertible.
#
# So `mcp-logs-Claude-Code-Remote` is the sanitized form of `Claude_Code_Remote`,
# whose live tool is `mcp__Claude_Code_Remote__list_sessions`. A predicate
# comparing an allow rule's server segment against these directory names reads
# the CORRECT underscore spelling as a misspelling of a name that does not exist.
# It fired, was read as confirmation, and the "fix" broke five working allow
# rules and both deny rules — including the two carrying AGENTS.md's ban on
# babysitting timers, which the change silently switched off.
#
# The question is worth answering and needs a source that PRESERVES the name:
# the tool names the session actually exposes, or the injected MCP config. Not
# this directory listing. Do not re-derive it from here.
#
# The declared exemption `hook-pin-check` honours, beside the assertion it
# describes rather than in a list that could drift from it.
#PIN-OK: jq
set -uo pipefail

# THE ONE THING THAT DOES NOT DROP jq (CLOUD-479), and it says so rather than
# leaving the reader to infer it from the registration. This gate's two `jq`
# calls read a settings FILE and an MCP `.jsonl` LOG — neither is a hook payload,
# so `payload-field`, which projects a field out of `hook::decode`, cannot serve
# either. `stop-guard` and `contract-drift` genuinely dropped `jq`; this one only
# moved by path, and the issue's checkbox is corrected on CLOUD-479 rather than
# quietly left unmet.
#
# Moving by path is what makes this check load-bearing. A by-path invocation does
# not get mise's env, so the pinned `"aqua:jqlang/jq"` becomes whatever
# `/usr/bin/jq` happens to be — or nothing at all. Absent, every read below would
# have failed into the `2>/dev/null` fallbacks and this gate would have reported
# a clean session while checking nothing. That is the precise trade CLOUD-479
# refuses: a latency fix must not convert a pinned dependency into a silent
# fail-open. So the dependency is asserted, loudly, before it is used.
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: mcp-attach-check: no jq on PATH — this gate reads a settings file and an MCP log, neither of which the payload reader can parse, so it is checking NOTHING. Run it through \`mise run mcp-attach-check\`, or install jq." >&2
	exit 2
fi

settings=".claude/settings.json"
logroot=""
spawns=""
spawns_set=0
while [ $# -gt 0 ]; do
	case "$1" in
	--settings)
		settings="${2:-}"
		shift 2
		;;
	--logs)
		logroot="${2:-}"
		shift 2
		;;
	--spawns)
		spawns="${2:-}"
		spawns_set=1
		shift 2
		;;
	*)
		echo "usage: mcp-attach-check [--settings <file>] [--logs <dir>] [--spawns <file>]" >&2
		exit 2
		;;
	esac
done

# The spawn ledger `mise-tasks/<server>-mcp` appends to (CLOUD-714). Out of tree,
# per clone, beside the other machinery under $GIT_DIR — the same place
# `contract-drift` keeps its snapshots, so no new path scheme is invented.
if [ "$spawns_set" = 0 ]; then
	git_dir=$(git rev-parse --git-dir 2>/dev/null) || git_dir=""
	[ -n "$git_dir" ] && spawns="$git_dir/batten-mcp-spawns"
fi

# The CLI keys its log tree by the project path with every `/` replaced by `-`,
# so `/home/user/batten` becomes `-home-user-batten`. Derived rather than
# hardcoded: a worktree under .claude/worktrees/ is a different project path and
# writes to a different tree, exactly as Serena itself keys by path.
if [ -z "$logroot" ]; then
	logroot="${HOME}/.cache/claude-cli-nodejs/$(pwd | tr '/' '-')"
fi

if [ ! -f "$settings" ]; then
	echo "mcp-attach-check: no $settings — nothing to check"
	exit 0
fi
if ! servers=$(jq -r '(.enabledMcpjsonServers // empty) | if type == "array" then .[] else empty end' "$settings" 2>/dev/null); then
	echo "::error:: $settings is not readable JSON" >&2
	exit 2
fi
if [ -z "$servers" ]; then
	echo "mcp-attach-check: no enabled .mcp.json servers — nothing to check"
	exit 0
fi

# FAIL OPEN on a missing log ROOT, and only there. No root at all means this is
# not a live CLI session — CI, a bare checkout, a different harness — and a gate
# that cannot look must never report a verdict it did not compute. A root that
# EXISTS with a server's directory missing is the opposite: the session logged
# every other server and none for this one, which is the defect itself.
if [ ! -d "$logroot" ]; then
	echo "mcp-attach-check: no MCP log tree at $logroot — not a live session, nothing to check"
	exit 0
fi

# --- did the client actually spawn it? (CLOUD-714) ---------------------------
#
# A `CONNECT_TIMEOUT` with no trace anywhere has two causes that look identical
# from the logs: the client never executed the command, or it executed it and the
# child died inside Serena's ~1.2 s of Python import, before Serena opens the log
# file that would prove it ran. Three failures on 2026-08-19 could not be told
# apart, which is what the shim's ledger is for.
#
# THE ABSENCE OF A LEDGER ENTRY IS ONLY EVIDENCE IF THE SHIM IS WIRED. A server
# launched directly, or a clone whose ledger has been cleaned, has no entries for
# an innocent reason — reporting `never-spawned` there would be a verdict computed
# from nothing, which is the failure mode this whole gate's header argues against.
# So the ledger must carry at least one record for THAT server before its silence
# about a particular attempt is allowed to mean anything.
#
# The attempt's instant comes from the log's FILENAME, which is the connection
# attempt's UTC start — already the key this gate sorts on, so no second notion of
# "when" is introduced. A spawn is matched to it inside a tolerance spanning the
# client's own budget: the shim records before `exec`, so it lands at the start,
# and 5 s of slack absorbs clock granularity in both directions.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT spawn-window-ignored|s@\$1 >= t - 5 && \$1 <= t + 35@1@|reads as never-spawned
#MUTANT ledger-wiring-inverted|s@if ! grep -q@if grep -q@|reads as spawned-and-unresponsive
spawn_verdict() { # spawn_verdict <server> <newest-log-path>
	local server="$1" log="$2" stamp start hits
	if [ -z "$spawns" ] || [ ! -r "$spawns" ]; then
		echo "unrecorded (no spawn ledger; wire mise-tasks/${server}-mcp to tell a launch that never happened from one that hung)"
		return 0
	fi
	if ! grep -q "$(printf '\t%s\t' "$server")" "$spawns" 2>/dev/null; then
		echo "unrecorded (the ledger has never seen $server; the shim is not wired for it)"
		return 0
	fi
	# `2026-08-11T05-41-40-873Z.jsonl` -> `2026-08-11T05:41:40Z`. The millisecond
	# field is dropped rather than parsed: the tolerance below is seconds wide, so
	# sub-second precision buys nothing and `date` portability costs something.
	stamp=$(basename -- "$log" .jsonl)
	stamp=$(printf '%s' "$stamp" | sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})-[0-9]+Z$/\1T\2:\3:\4Z/')
	if ! start=$(date -u -d "$stamp" +%s 2>/dev/null) || [ -z "$start" ]; then
		echo "unrecorded (the log name carries no parseable attempt time)"
		return 0
	fi
	hits=$(awk -F'\t' -v s="$server" -v t="$start" \
		'$1 ~ /^[0-9]+$/ && $2 == s && $1 >= t - 5 && $1 <= t + 35 { n++ } END { print n + 0 }' \
		"$spawns" 2>/dev/null) || hits=0
	if [ "${hits:-0}" -gt 0 ]; then
		echo "spawned-and-unresponsive (the shim recorded the launch; the child ran and did not answer)"
	else
		echo "never-spawned (the shim records every launch and recorded none for this attempt)"
	fi
}

fail=0
report() {
	[ "$fail" = 0 ] && echo "::error:: enabled MCP server(s) did not attach this session (see mem:serena-setup):" >&2
	printf '  %s\n' "$1" >&2
	fail=1
}

while IFS= read -r server; do
	[ -n "$server" ] || continue
	dir="$logroot/mcp-logs-$server"
	if [ ! -d "$dir" ]; then
		report "$server no-log — enabled, but this session logged no connection attempt for it"
		continue
	fi

	# Newest by NAME, not by mtime. Each connection attempt opens its own file
	# named for its UTC start instant — `2026-08-11T06-19-12-114Z.jsonl` — a
	# fixed-width ISO-8601 form whose lexicographic order IS its chronological
	# order, so a plain reverse sort picks this session's log. Parsing `ls -t`
	# would be the obvious alternative and is the wrong one (SC2012): its output
	# is ambiguous for unusual filenames, and mtime is the weaker key anyway —
	# a log is appended to as the session runs, so mtime tracks last write while
	# the name records which connection attempt it belongs to.
	newest=$(find "$dir" -maxdepth 1 -type f -name '*.jsonl' 2>/dev/null | sort -r | head -n 1)
	if [ -z "$newest" ] || [ ! -r "$newest" ]; then
		report "$server no-log — $dir holds no readable connection log"
		continue
	fi

	# The LAST outcome record decides. `Connection failed` carries its reason in
	# parentheses (`CONNECT_TIMEOUT`, `-32000`, …); that string is the pointer,
	# and it is the only part of the line that is ever printed.
	outcome=$(jq -r 'select(has("debug")) | .debug
		| if startswith("Successfully connected") then "ok"
		  elif startswith("Connection failed") then
		      "fail " + ((capture("\\((?<c>[^)]+)\\)") | .c) // "unknown")
		  else empty end' "$newest" 2>/dev/null | tail -n 1)

	case "$outcome" in
	ok) ;;
	"fail "*) report "$server ${outcome#fail } — $(spawn_verdict "$server" "$newest")" ;;
	*) report "$server no-outcome — its newest log records no connection result" ;;
	esac
done <<<"$servers"

[ "$fail" = 0 ] && echo "mcp-attach-check: every enabled MCP server attached this session"
exit "$fail"
