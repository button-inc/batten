#!/usr/bin/env bash
#MISE description="Recover this session's own `get_issue` payloads from its transcript, so a sweep pays the fetch once (CLOUD-782)"
#
# CLOUD-782. Every board gate declares the field set it reads (CLOUD-526), and the
# tracker's read surface cannot honour those declarations: `list_issues` projects
# fields but its enum carries neither `attachments` nor `relations`, and
# `get_issue` returns both and takes no field selection. So a sweep pays ~4.5k
# tokens per issue to decide on ~1.6k. That third is structural and this task does
# not touch it.
#
# WHAT IT DOES REMOVE IS THE SECOND COPY. Without this, a payload reaches a gate's
# stdin only by an agent re-typing it — and a paraphrase into a gate payload is
# the forged-compliance shape CLOUD-526 measured seven times. The session's own
# transcript already holds the bytes the tracker returned, so recovering them is
# byte-perfect where transcription is not, and free where transcription is not.
#
# ─── IDENTIFY BY TOOL NAME, NEVER BY FIELD PRESENCE ──────────────────────────
#
# This is the whole correctness argument, and it is the one a prototype got wrong
# three times in a single session before the rule was found.
#
# A `save_issue` response and a `get_issue` payload are SHAPE-IDENTICAL across
# `id`, `status` and `attachments`. They differ only in that `save_issue` omits
# `relations`. So a discriminator like `if "attachments" in obj` matches BOTH, and
# since a board write usually follows a read, the later and poorer payload wins —
# silently dropping `relations`, which `graph-check` then refuses as
# `unjudgeable-blockedby`. The cache looks populated and is not.
#
# The transcript records the tool NAME on the `tool_use` block and the payload on
# the matching `tool_result`, joined by `tool_use_id`. Measured on one session:
# 1841 named `tool_use` blocks, 1839 `tool_result` blocks, and 1839 of 1839
# joinable — the join is total, not best-effort. Over the same session, 143
# `get_issue` calls against 146 `save_issue` calls: near-equal volume, which is
# why duck-typing loses consistently rather than occasionally.
#
# MATCH THE SUFFIX AFTER THE LAST `__`, NEVER THE WHOLE NAME. That same session
# recorded both `mcp__4db58e41-…__get_issue` and `mcp__Linear__get_issue`: the MCP
# server reconnected under a different alias mid-session, which is CLOUD-178's
# connector-naming instability. A full-name match harvests nothing after a
# reconnect, and reports success while doing it.
#
# NEWEST *QUALIFYING* PAYLOAD WINS — newest among those from a `get_issue` call.
# CLOUD-782 §2 says "the newest `get_issue` payload per id" and never says how to
# identify one; that gap is what this header closes.
#
# ─── WHAT A RECOVERED PAYLOAD IS AND IS NOT ──────────────────────────────────
#
# It carries the row's STRUCTURE faithfully. It does NOT carry freshness, and the
# distinction is load-bearing rather than pedantic: measured twice on 2026-08-20,
# the corrected predicate returned the right `relations` beside a STALE `status`,
# because the row had moved since the read. A caller that promotes on a cached
# `status` moves a row on last hour's board. Recover structure here; re-read the
# row before deciding its state. `issue-read-check` bounds the age of a read for
# exactly this reason and is the caller's tool for it.
#
# The transcript is the richest secret surface the engine can be pointed at
# (`transcript.rs`'s own doc), so the report is a count and ids and never a byte
# of a body (non-negotiable rule 4).
#
# The mutations target the two halves of the identification rule.
#MUTANT board-payloads-matches-any-issue-tool|s@endswith("__get_issue")@length >= 0@|CLOUD-782: a LATER save_issue response does not displace the get_issue payload
#MUTANT board-payloads-matches-full-tool-name|s@endswith("__get_issue")@== "mcp__Linear__get_issue"@|CLOUD-782: a reconnected server alias still matches on the suffix
# CLOUD-1033. Neutering the whole-file decode check must fail the torn-transcript
# case; if it does not, that case is asserting something else.
#
# The character class is load-bearing, not a typo: without it the pattern matches
# THIS DECLARATION LINE first and mutates its own row rather than the code, which
# is the `self-mutating-row` shape CLOUD-480 refuses and CLOUD-941 recorded twice.
# Same trick as `board-write-record`'s ` --n[a]med `. Field 3 is a bats --filter,
# never a description — a title that matches no case reports `names-no-case`.
#MUTANT board-payloads-decode-failure-is-an-empty-harvest|s@if ! decode_erro[r]=@if false \&\& ! decode_error=@|CLOUD-1033: a transcript with an undecodable line
set -euo pipefail

usage() {
	echo "usage: board-payloads <CLOUD-id>... (writes one payload per id into BOARD_PAYLOADS_DIR)" >&2
	exit 2
}

[[ "$#" -ge 1 ]] || usage
for id in "$@"; do
	case "$id" in
	CLOUD-[0-9]*) ;;
	*) usage ;;
	esac
done

#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: board-payloads: no jq on PATH — the transcript could not be read. Run: mise install" >&2
	exit 2
fi

# INJECTABLE, for the reason `transcript-corpus-check:88` gives about its own
# root: a live host produces exactly one transcript, so a suite that could not
# vary it would ship as coverage while exercising a single row (CLOUD-418).
#
# The default is `batten.toml`'s `[transcript] path` — the symlink `stop-guard`
# refreshes from each Stop payload's own `transcript_path`. That file's header
# explains why the indirection lives there rather than in config: "the authority
# names one file forever; which session it is, is the host's fact."
transcript="${BATTEN_TRANSCRIPT_FILE:-.claude/.transcript.jsonl}"
out="${BOARD_PAYLOADS_DIR:-.git/batten-payloads}"

# ABSENT IS COULD-NOT-LOOK, NEVER AN EMPTY HARVEST. A fresh checkout, a
# non-Claude host, or a session whose Stop hook has not yet run all resolve here,
# and `Capability::Absent` is the reading `batten.toml` already documents for
# them. Reporting "0 recovered" would be a clean answer to a question never asked.
if [[ ! -r "$transcript" ]]; then
	echo "::error:: board-payloads: no readable transcript at $transcript — the payloads could not be recovered. This is not an empty harvest." >&2
	# THE CANONICAL RECIPE FOR THE OTHER SOURCE, and the reason it is spelled here
	# rather than left to the reader: a host with no transcript at all — a CCR
	# container writes none — makes this task structurally unable to answer, and
	# every gate that wants a payload sends the agent HERE. Saying only "could not
	# recover" is what CLOUD-990 measured: an agent concluded the board could not
	# be written from this host, reported it as a blocker twice, and could not even
	# file that finding, because the filing gate wants the same bytes.
	#
	# The capture store (CLOUD-919/918) holds the tracker's own response bytes, so
	# it satisfies the forgery-resistance argument in this file's header in full —
	# it is a second honest source, not a way around the rule.
	cat >&2 <<-'ELSEWHERE'
		::error:: board-payloads: the same bytes are in the capture store, which needs no transcript:
		::error::     batten capture list
		::error::     batten capture show <handle> --grep '"id":"CLOUD-N"'   # find the handle
		::error::     batten capture show <handle> --raw | mise run issue-read-check
		::error:: Those are bytes the tracker returned, not a re-typed copy, so they are as valid here as a recovered payload.
	ELSEWHERE
	exit 2
fi

mkdir -p "$out" || {
	echo "::error:: board-payloads: cannot create $out" >&2
	exit 2
}

# Two passes over one file: collect `tool_use_id -> tool name`, then keep the
# newest payload whose originating call was a `get_issue`. Streamed with `jq -n`
# rather than slurped — a session transcript runs to tens of megabytes.
# UNDECODABLE CONTENT IS COULD-NOT-LOOK TOO, and it is decided ONCE, before any
# id is attempted (CLOUD-1033). The header above promises this for the file and
# line 99 delivers it; the loop below did not deliver it for the file's CONTENT.
#
# `jq -n '[inputs]'` reads the WHOLE file, so one undecodable line aborts the
# parse for EVERY id. Recovering per-id and swallowing the diagnostic turned that
# into the same empty string a genuine miss produces, and the summary then said
# `recovered 0 of N` — a statement about what the transcript CONTAINS, made
# without ever having read it. Measured 2026-08-24: a session was told CLOUD-819
# was not in its transcript while the payload sat there behind a torn line at
# 5204, written by a harness whose framing this tree cannot fix (CLOUD-1032).
#
# Deciding it once rather than per-id is what keeps the two answers apart: after
# this, an empty result from the loop can ONLY mean the id is absent.
#
# Pointer-only (rule 4): jq's own message names the line and column, and nothing
# from the line itself is echoed. A transcript is the richest secret surface
# anything here reads.
if ! decode_error=$(jq -e . "$transcript" 2>&1 >/dev/null); then
	echo "::error:: board-payloads: the transcript at $transcript did not decode, so no payload could be recovered. This is not an empty harvest." >&2
	# jq prints `jq: error (at <file>:N)` or `parse error: … at line N, column M`;
	# either way the pointer is the tail of its own message and never the line.
	printf '::error:: board-payloads: %s\n' "${decode_error##*$'\n'}" >&2
	cat >&2 <<-'ELSEWHERE'
		::error:: board-payloads: the same bytes are in the capture store, which needs no transcript:
		::error::     batten capture list
		::error::     batten capture show <handle> --raw | grep -c '"id":"CLOUD-N"'   # find the handle; --grep exits 0 either way
		::error::     batten capture show <handle> --raw | mise run issue-read-check
		::error:: Those are bytes the tracker returned, not a re-typed copy, so they are as valid here as a recovered payload.
	ELSEWHERE
	exit 2
fi

for id in "$@"; do
	payload=$(jq -rn --arg id "$id" '
		[inputs] as $lines
		| ($lines
		   | map(.. | objects | select(.type? == "tool_use" and (.name? | type == "string")))
		   | map({(.id): .name}) | add // {}) as $names
		| $lines
		| map(.. | objects
		      | select(.type? == "tool_result")
		      | select($names[.tool_use_id] // "" | endswith("__get_issue"))
		      | .content?)
		| map(.. | strings)
		| map(select(startswith("{")))
		| map(fromjson? // empty)
		| map(select(.id? == $id))
		| last // empty
		| tojson
	' "$transcript" 2>/dev/null) || payload=""
	if [[ -n "$payload" ]]; then
		printf '%s\n' "$payload" >"$out/$id.json"
	fi
done

# Pointer-only (rule 4): counts and ids, never a byte of a body.
found=0
missing=""
for id in "$@"; do
	if [[ -s "$out/$id.json" ]]; then
		found=$((found + 1))
	else
		missing="$missing $id"
	fi
done

echo "board-payloads: recovered $found of $# payload(s) into $out"
if [[ -n "$missing" ]]; then
	echo "::error:: board-payloads: no \`get_issue\` payload in this session's transcript for:$missing. Fetch them with get_issue(includeRelations: true) and run this again — sweeping a short closure is what the board gates refuse." >&2
	exit 1
fi
exit 0
