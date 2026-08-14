#!/usr/bin/env bash
#MISE description="PreToolUse hook body: deny creating a tracker issue on a branch that carries no search receipt, so a duplicate is seen before it is filed"
#
# CLOUD-505. The pure decision is `issue-search-check`, which owns the reasoning
# and mints the receipt; this file is the adapter, split for the same reason
# the claim gate is split from `claim-check` — the decision stays directly
# callable and directly testable, and the receipt path is spelled in both places
# only because a hook cannot shell out to a second task per tool call.
#
# ONLY CREATES ARE GATED, and the discriminator is already proven here:
# `finding-sink-check` tells the two apart with `save_issue#noid`. A `save_issue`
# carrying no `id` opens a row; one carrying an `id` annotates a row that already
# exists. Denying an update would demand a search before every edit to an issue,
# which is absurd and would get the guard switched off within a day.
#
# THE MATCHER THAT WIRES THIS MUST BE SUFFIX-ANCHORED, and this file cannot
# enforce that — it is `.claude/settings.json`'s to get right. CLOUD-178 measured
# the same connector exposed as `mcp__Linear__save_issue`, `mcp__<uuid>__save_issue`
# and `mcp__claude_ai_Linear__save_issue` depending on the registration episode,
# so a rule naming one matches none of the others and the miss is silent. This
# body therefore ALSO matches on the suffix rather than trusting the wiring, so a
# prefix-anchored matcher degrades to "never fires" rather than to "fires on the
# wrong tool".
#
# FAILS OPEN on everything it cannot establish, exactly as the claim receipt does: an
# unparseable payload, no git dir, a detached HEAD, or the bypass. A guard that
# blocked filing because it could not read its own inputs would be worse than the
# gap it closes — the board is how anything gets recorded at all.
#
# The mutation is the collapse this file exists to prevent: stop discriminating
# create from update, and every edit to an existing issue demands a search, which
# is how a guard gets switched off within a day.
#MUTANT update-gated-too|s/^\[ -n "\$existing" \] && exit 0$/[ -n "$existing" ] \&\& :/|updating an existing issue is never gated
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
	echo "::error:: issue-search-guard: no jq on PATH — this guard is registered by path, so it does not get mise's pinned jq. It is checking NOTHING and allowing every call. Run: mise install" >&2
	exit 0
fi

[ -n "${BATTEN_ISSUE_SEARCH_BYPASS:-}" ] && exit 0

raw=$(cat) || exit 0

tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[ -n "$tool" ] || exit 0

# Suffix, never prefix — see the header. `save_issue` is the only creating verb;
# `save_comment`, `save_document` and the rest attach to something that exists.
case "$tool" in
*save_issue) ;;
*) exit 0 ;;
esac

# An `id` in the input means this updates an existing row, which needs no search.
# `// empty` collapses null and absent, so both read as a create only when the
# key is genuinely missing.
existing=$(printf '%s' "$raw" | jq -r '.tool_input.id // empty' 2>/dev/null) || exit 0
[ -n "$existing" ] && exit 0

git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0
[ -n "$git_dir" ] || exit 0
branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || exit 0
[ -n "$branch" ] || exit 0

receipt="$git_dir/batten-receipts/issue-search.${branch//\//-}"
[ -f "$receipt" ] && exit 0

# Pointer-only (non-negotiable 4): the branch and the command that fixes it.
# Never a title, never a body, and deliberately no guess about what this might be
# a duplicate OF — the gate does not know, and pretending to would be the model
# verdict non-negotiable 3 refuses.
jq -n --arg b "$branch" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: (
      "Refused: branch \"" + $b + "\" carries no issue-search receipt, so this would file a row without anyone having looked for an existing one.\n\nEvery other path onto the board is gated — claim-check, the mediated claim receipt, issue-guard, ready-lint, graph-check. Filing was not, and it cost a measured 45 minutes of re-deriving a cause that was already filed, plus two wrong diagnoses reported to a human, before a duplicate was opened (CLOUD-505).\n\nSearch first, then record it:\n\n  mcp__Linear__list_issues with a query drawn from the finding\n  ... pipe that payload to: mise run issue-search-check\n\nA search that returns nothing still mints the receipt — zero hits is the honest outcome for a genuinely new finding, and is not refused.\n\nThis does not judge whether you are filing a duplicate; it cannot, and a gate that guessed would be a model verdict. It only refuses to let the question go unasked. Updating an existing issue is never gated. Bypass with BATTEN_ISSUE_SEARCH_BYPASS=1."
    )
  }
}'
