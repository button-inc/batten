#!/usr/bin/env bash
#MISE description="PreToolUse hook body: deny an issue update written against a read older than the bound, so a groom cannot land on a row that changed underneath it"
#
# CLOUD-508. `issue-read-check` carries the diagnosis and owns the receipt path;
# this file is the adapter, split for the same reason `issue-search-check` and
# `issue-search-guard` are — the decision stays directly callable and directly
# testable, and the receipt path is spelled in exactly two places.
#
# THIS IS THE COMPLEMENT OF `issue-search-guard`, not a duplicate of it, and the
# two are wired into the same matcher group on purpose. That one gates CREATES:
# it exits 0 the moment `.tool_input.id` is present, and its refusal text says
# outright that "updating an existing issue is never gated". Which was true, and
# is the hole this closes. Same tool, opposite arm, one settings block.
#
# Fails OPEN on everything it cannot establish, and on BATTEN_ISSUE_READ_BYPASS=1.
#
# The mutation turns the recency test back into an existence test — a receipt of
# any age authorises the write. That is precisely the gate the claim receipt and
# `issue-search-guard` implement for their own questions, and precisely what let
# the CLOUD-504 groom through, so every DENY row for a MISSING receipt still
# passes under it. Only the aged rows can catch it.
#MUTANT any-receipt-authorises|s/\[ "\$age" -le "\$max_age" \]/[ "$age" -ge 0 ]/|an update from a read older than the bound is denied
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT deny-decision-becomes-allow|s/permissionDecision: "deny"/permissionDecision: "allow"/|an update with no receipt is denied

set -uo pipefail

#
# CLOUD-479's pairing, declared rather than discovered. This hook is registered
# BY PATH, so it does not get mise's env and the `"aqua:jqlang/jq"` pin below
# does not reach it — `jq` is whatever the ambient PATH holds, or nothing. Every
# read here is fail-open, so an absent `jq` would not error: it would ALLOW,
# silently, which is the one outcome a guard must never reach by accident.
#
# Asserted loudly and still open. A `PreToolUse` hook's exit 2 is a DENY, so a
# missing parser must not take that channel — it says so on stderr and gets out
# of the way, which is loud where it used to be silent while never blocking a
# call over a broken toolchain.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: issue-read-guard: no jq on PATH — this guard is registered by path, so it does not get mise's pinned jq. It is checking NOTHING and allowing every call. Run: mise install" >&2
	exit 0
fi

[[ -n "${BATTEN_ISSUE_READ_BYPASS:-}" ]] && exit 0

raw=$(cat) || exit 0

tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[[ -n "$tool" ]] || exit 0

# Suffix, never prefix — CLOUD-178 measured the same connector exposed as
# `mcp__Linear__save_issue` and as `mcp__<uuid>__save_issue` inside one session,
# so a prefix anchor gates one spelling and silently misses the others. The
# matcher in settings.json is written the same way; this re-checks rather than
# trusting it, exactly as `issue-search-guard` does.
case "$tool" in
*save_issue) ;;
*) exit 0 ;;
esac

# NO `id` MEANS A CREATE, which is `issue-search-guard`'s arm and never this
# one. `// empty` collapses null and absent so both read as a create only when
# the key is genuinely missing.
key=$(printf '%s' "$raw" | jq -r '.tool_input.id // empty' 2>/dev/null) || exit 0
[[ -n "$key" ]] || exit 0

# The `id` parameter accepts a UUID as well as an issue key, and the receipt
# namespace is keyed by KEY. A UUID cannot be resolved to one without a tracker
# credential, which a hook does not have — so this is a genuine "cannot look",
# and it allows. Denying instead would refuse a legitimate update over a spelling
# the agent is entitled to use, which is the false-positive rate that gets a
# guard bypassed and then enforces nothing.
case "$key" in
[A-Z]*-[0-9]*) ;;
*) exit 0 ;;
esac

git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0
[[ -n "$git_dir" ]] || exit 0

# Must match `issue-read-check`'s spelling exactly.
receipt="$git_dir/batten-receipts/issue-read.$key"

max_age=${BATTEN_ISSUE_READ_MAX_AGE:-300}

deny() {
	jq -n --arg k "$key" --arg why "$1" --arg m "$max_age" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: (
      "Refused: this would update " + $k + " from " + $why + ".\n\n`save_issue` takes no if-match precondition, so an update always wins over whatever landed since you read the row. Measured 2026-08-13: a session read CLOUD-504, planned against it for ~51 minutes, and wrote a Ready block moving it into the ready queue — another session had marked it a duplicate in between, and the write landed anyway (CLOUD-508).\n\nRe-read it, then record the read:\n\n  get_issue " + $k + " (includeRelations: true)\n  ... pipe that payload to: mise run issue-read-check\n\nThe payload comes from `mise run board-payloads " + $k + "` on a host with a transcript, or from the capture store on any host (CLOUD-990): `batten capture list`, then `batten capture show <handle> --grep \"" + $k + "\"` to find it, then `batten capture show <handle> --raw | mise run issue-read-check`. A CCR container writes no transcript, so there the capture store is the only route — and it hands over bytes the tracker returned, so it is as valid as a recovered payload. Do not re-type a payload by hand.\n\nThen make the write from what you just read, not from the plan you built earlier. If the row changed, that is the point — decide again.\n\nThis bounds how old the read was; it cannot prove the row is unchanged, because the tracker offers no precondition on write. Creating an issue is never gated here (that is issue-search-guard). Bypass with BATTEN_ISSUE_READ_BYPASS=1."
    )
  }
}'
	exit 0
}

[[ -f "$receipt" ]] || deny "a read this clone has no record of"

# Field 3 is the local epoch `issue-read-check` stamped. An unreadable or
# non-numeric receipt is a cannot-look, not a verdict — the same distinction
# `alive` draws between a corpse and a free lock.
read_at=$(awk 'NR==1{print $3}' "$receipt" 2>/dev/null) || exit 0
case "$read_at" in
'' | *[!0-9]*) exit 0 ;;
esac

now=$(date -u +%s 2>/dev/null) || exit 0
age=$((now - read_at))

# A receipt from the future is a clock that moved, not a fresh read. Treated as
# cannot-look rather than as authorisation, because the alternative is that any
# clock skew mints an unbounded licence.
[[ "$age" -ge 0 ]] || exit 0

[[ "$age" -le "$max_age" ]] || deny "a read ${age}s old, past the ${max_age}s bound"

exit 0
