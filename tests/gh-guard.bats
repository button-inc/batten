#!/usr/bin/env bats
# The gate that ships with the gh guard (AGENTS.md non-negotiable 2): the policy
# table must block exactly the hand-rolled shapes and nothing else.
#
# The ALLOWED cases carry as much weight as the blocked ones. A guard with false
# positives gets bypassed, and a bypassed guard enforces nothing — this suite
# exists because the first live run of the guard denied a `git commit` whose
# MESSAGE quoted the blocked verbs.

setup() {
  CHECK="$BATS_TEST_DIRNAME/../mise-tasks/gh-guard-check"
  GUARD="$BATS_TEST_DIRNAME/../mise-tasks/gh-guard"
}

# --- blocked: shapes a task already encapsulates ------------------------------

@test "blocks gh pr merge" {
  run "$CHECK" 'gh pr merge 42 --rebase'
  [ "$status" -eq 1 ]
  [[ "$output" == *"mise run land"* ]]
}

@test "blocks gh pr merge behind a flag value" {
  run "$CHECK" 'gh -R button-inc/batten pr merge 42'
  [ "$status" -eq 1 ]
}

@test "blocks gh pr merge behind an env prefix" {
  run "$CHECK" 'GH_TOKEN=x gh pr merge 42'
  [ "$status" -eq 1 ]
}

@test "blocks gh pr checks" {
  run "$CHECK" 'gh pr checks 63 --watch'
  [ "$status" -eq 1 ]
  [[ "$output" == *"mise run ci-wait"* ]]
}

@test "blocks gh run watch" {
  run "$CHECK" 'gh run watch 12345'
  [ "$status" -eq 1 ]
}

@test "blocks a blocked verb hiding in a later chained segment" {
  run "$CHECK" 'gh pr view 63 && gh run watch 1'
  [ "$status" -eq 1 ]
  run "$CHECK" 'echo hi; gh pr checks 63'
  [ "$status" -eq 1 ]
}

@test "blocks a hand-typed /fast-forward comment" {
  run "$CHECK" 'gh pr comment 63 --body "/fast-forward"'
  [ "$status" -eq 1 ]
  [[ "$output" == *"mise run land"* ]]
}

# --- allowed: reads, creates, and verbs with no task wrapper -------------------

@test "allows gh pr ready" {
  run "$CHECK" 'gh pr ready 63'
  [ "$status" -eq 0 ]
}

@test "allows gh pr reads" {
  for c in 'gh pr view 63 --json state' 'gh pr list --state open' 'gh pr create --draft --fill'; do
    run "$CHECK" "$c"
    [ "$status" -eq 0 ]
  done
}

@test "allows a branch argument that merely contains a blocked verb" {
  run "$CHECK" 'gh pr view merge-fix --json state'
  [ "$status" -eq 0 ]
}

@test "allows an ordinary gh pr comment" {
  run "$CHECK" 'gh pr comment 63 --body "CI is green"'
  [ "$status" -eq 0 ]
}

@test "allows gh api and the unblocked run subcommands" {
  for c in 'gh api repos/o/r/commits/abc/check-runs' 'gh run view 12345 --log' 'gh run rerun 12345' 'gh workflow run ci.yml'; do
    run "$CHECK" "$c"
    [ "$status" -eq 0 ]
  done
}

@test "allows a non-gh command that quotes a blocked verb" {
  # The regression: a commit message naming the verbs is not a call.
  run "$CHECK" 'git commit -m "ci(guard): block gh pr merge and a typed /fast-forward comment"'
  [ "$status" -eq 0 ]
  run "$CHECK" 'echo "gh run watch"'
  [ "$status" -eq 0 ]
}

@test "allows an empty command" {
  run "$CHECK" ''
  [ "$status" -eq 0 ]
}

# --- the hook wrapper ----------------------------------------------------------

@test "hook emits a deny decision for a blocked command" {
  run bash -c "printf '%s' '{\"tool_input\":{\"command\":\"gh pr merge 63\"}}' | '$GUARD'"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"permissionDecision": "deny"'* ]]
}

@test "hook stays silent for an allowed command" {
  run bash -c "printf '%s' '{\"tool_input\":{\"command\":\"gh pr ready 63\"}}' | '$GUARD'"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "hook fails open on unparseable input" {
  run bash -c "printf '%s' 'not json' | '$GUARD'"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "hook honours the bypass" {
  run bash -c "printf '%s' '{\"tool_input\":{\"command\":\"gh pr merge 63\"}}' | BATTEN_GH_GUARD_BYPASS=1 '$GUARD'"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
