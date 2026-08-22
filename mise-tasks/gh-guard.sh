#!/usr/bin/env bash
#MISE description="PreToolUse hook body: deny a Bash call that hand-rolls a gh lifecycle/CI-watch shape this repo routes through a task"
#
# Wired from .claude/settings.json. Thin by design — the decision lives in
# `gh-guard-check`, where it is unit-tested by `gh-guard-test`.
#
# Fails OPEN on anything it cannot read or parse, and on BATTEN_GH_GUARD_BYPASS —
# the escape hatch for a human who genuinely must run raw gh. (The tasks
# themselves shell out to gh from a subprocess this hook never sees, so they need
# no bypass.)
set -uo pipefail

[[ -n "${BATTEN_GH_GUARD_BYPASS:-}" ]] && exit 0

raw=$(cat) || exit 0
cmd=$(printf '%s' "$raw" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -n "$cmd" ]] || exit 0

reason=$(mise run gh-guard-check "$cmd" 2>/dev/null) && exit 0
[[ -n "$reason" ]] || exit 0

jq -n --arg r "$reason" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: $r
  }
}'
