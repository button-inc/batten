#!/usr/bin/env bash
#MISE description="MCP launcher shim: record that the client actually spawned this server, then exec the real launch line unchanged (CLOUD-714)"
#
# CLOUD-714. Serena failed to attach three times on 2026-08-19, each time burning
# ~28,300 ms of a 30,000 ms budget and leaving NO trace anywhere: no serena log,
# no `Server stderr:` record in the client's own log, nothing. Two very different
# failures produce that exact signature —
#
#   * the client never executed the configured command at all; or
#   * it executed it and the child died before Serena opened its log file, which
#     is ~1.2 s of Python import into the process (2,664 files, 107 MB).
#
# Nothing in this repo could tell those apart, so a day went into archaeology
# across two log trees and a directory mtime and still could not answer it. This
# is that answer, made a file read: the FIRST thing this script does is append a
# line saying it ran, and the LAST is `exec` the launch line byte-for-byte as
# `.mcp.json` used to spell it. A `CONNECT_TIMEOUT` with a matching record means
# spawned-and-unresponsive; one without means never spawned. `mcp-attach-check`
# makes that comparison.
#
# WHAT THIS MUST NEVER BECOME, and the constraint is the point of the issue: not
# a retry, not a supervisor, not a keepalive. It records and it execs. Anything
# that restarted the server on failure would hide the defect this exists to
# expose — and `exec` is what enforces it structurally, since after it there is
# no shell left to supervise anything.
#
# THE TWO EXTRA FIELDS ARE NOT DECORATION. The only correlate that survived
# elimination is that all three failures happened during a multi-server startup
# burst — Serena spawned alongside four other transports — while every one of the
# five successful isolated replications (3.1–7.3 s) was a lone launch on an idle
# session. That is n=3 with no mechanism attached, so it is a hypothesis, and the
# load average and the sibling count are what let the NEXT occurrence decide it.
# Both are free at spawn and unrecoverable afterwards.
#
# STDOUT IS THE MCP TRANSPORT. Not a diagnostic channel, not a place to echo what
# was recorded: one stray byte here corrupts the JSON-RPC stream and takes the
# server down in a way that looks exactly like the bug. Everything below writes
# to the ledger or to stderr, and every step is failure-tolerant — a ledger that
# cannot be written must never be the reason a server does not start.
set -u

# The server this shim fronts, taken from its own basename (`serena-mcp` →
# `serena`) so a second server is a second name and not a second script. The env
# override exists for the suite, which runs the shim under a fixture name.
server="${BATTEN_MCP_SERVER:-}"
if [ -z "$server" ]; then
	server=$(basename -- "$0")
	server="${server%-mcp}"
fi

# The window in which two spawns count as concurrent, and the one number here
# that is a judgement rather than a reading. Ten seconds is a third of the
# client's connect budget: long enough that a burst of servers started back to
# back all land inside it, short enough that the previous session's launches do
# not.
window="${BATTEN_MCP_SPAWN_WINDOW:-10}"

# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT record-never-written|s@^record .*@:@|appends one record naming the server
#MUTANT forks-instead-of-execing|s@^exec @@|execs rather than forks
#MUTANT siblings-always-zero|s@now - \$1 <= w@0@|counts the earlier one as a sibling
record() {
	local git_dir now load ledger siblings
	# Outside a checkout there is nowhere per-clone to keep the ledger, and
	# inventing a path under $TMPDIR would put it somewhere no gate reads.
	git_dir=$(git rev-parse --git-dir 2>/dev/null) || return 0
	[ -n "$git_dir" ] || return 0
	ledger="$git_dir/batten-mcp-spawns"
	now=$(date +%s 2>/dev/null) || return 0
	# 1-minute load, first field of /proc/loadavg. `?` rather than a guess when
	# the file is unreadable: the field must never silently become a number that
	# reads as "the machine was idle".
	load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null) || load=""
	[ -n "$load" ] || load="?"
	# Siblings are counted from this same ledger — entries inside the window that
	# are already there — so there is no process-table walk and no new dependency.
	# Counted BEFORE the append, so a launch never counts itself.
	siblings=0
	if [ -f "$ledger" ]; then
		siblings=$(awk -v now="$now" -v w="$window" \
			'$1 ~ /^[0-9]+$/ && now - $1 <= w && now - $1 >= 0 { n++ } END { print n + 0 }' \
			"$ledger" 2>/dev/null) || siblings=0
	fi
	[ -n "$siblings" ] || siblings=0
	# `>>` on a short line is atomic enough for concurrent appends here: the
	# record is well under PIPE_BUF and every writer opens in append mode.
	printf '%s\t%s\t%s\t%s\t%s\n' "$now" "$server" "$$" "$load" "$siblings" \
		>>"$ledger" 2>/dev/null || true
}

record || true

# The launch line, unchanged. `.mcp.json` still carries the scoped, pinned
# `exec pipx:serena-agent@<v> -- serena start-mcp-server …` argv it always did,
# so `mise-pin-agreement` still reads the pin out of it and CLOUD-316's scoped
# exec is still gated — the shim moved the COMMAND, deliberately not the args.
#
# `exec`, so the server's pid is the pid recorded above and no shell survives to
# become a supervisor. The launcher is an env var only so the suite can assert
# that property against something cheaper than a real MCP server.
exec "${BATTEN_MCP_LAUNCHER:-mise}" "$@"
