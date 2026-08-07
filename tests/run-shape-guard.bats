#!/usr/bin/env bats
# Two shapes that report success while destroying what the harness reads: a
# pager eating the exit status, and nohup/& orphaning the process. Both were
# used repeatedly in one session because both fail green.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

# --- piped-verdict ----------------------------------------------------------

@test "the shape that reported green over a failed verify is denied" {
	run guard 'mise run verify 2>&1 | tail -6'
	denied "$output"
	[[ "$output" == *"exit status"* ]]
}

@test "head masks the status exactly as tail does" {
	run guard 'mise run ci 2>&1 | head -20'
	denied "$output"
}

@test "the denial names the correct form rather than only refusing" {
	run guard 'mise run test:bats | tail -5'
	[[ "$output" == *"EXIT="* ]]
	[[ "$output" == *"run_in_background"* ]]
}

@test "redirect-then-inspect is the correct form and stays allowed" {
	run guard 'mise run verify >/tmp/v.log 2>&1; echo "EXIT=$?"'
	! denied "$output"
}

@test "a pager over a file is fine — it is a pager over a live task that is not" {
	run guard 'tail -20 /tmp/v.log'
	! denied "$output"
}

@test "an intermediate filter that is not a pager is not this guard's business" {
	# grep/jq change what is shown without being the documented exit-eating
	# shape; widening to every pipe would deny ordinary composition.
	run guard 'mise run graph-check | jq -r .ready'
	! denied "$output"
}

# --- orphaned-run -----------------------------------------------------------

@test "the nohup shape that orphaned land is denied" {
	run guard 'PR=105 nohup mise run land >/tmp/land.log 2>&1 & sleep 3; echo started'
	denied "$output"
	[[ "$output" == *"run_in_background"* ]]
}

@test "a bare trailing & is the same defect without nohup" {
	run guard 'mise run ci-wait &'
	denied "$output"
}

@test "&& is not a background operator and must not be caught" {
	run guard 'mise run linear-check && mise run commit-lint'
	! denied "$output"
}

# --- scope ------------------------------------------------------------------

@test "a non-mise command is not judged" {
	run guard 'git log --oneline | head -5'
	! denied "$output"
}

@test "mise exec runs a program directly and carries no gate verdict" {
	run guard 'mise exec -- bats tests/foo.bats | tail -3'
	! denied "$output"
}

@test "a commit message describing the shape is not the shape" {
	run guard 'git commit -m "explain why mise run verify | tail hides the exit code"'
	! denied "$output"
}

# --- failure posture --------------------------------------------------------

@test "the bypass is honoured" {
	BATTEN_RUN_SHAPE_BYPASS=1 run guard 'mise run verify | tail -1'
	! denied "$output"
}

@test "unparseable input fails open rather than blocking every command" {
	run bash -c "printf 'not json' | $GUARD"
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "an empty command fails open" {
	run bash -c "jq -nc '{tool_input:{}}' | $GUARD"
	! denied "$output"
}

@test "a heredoc body describing the shapes is not the shape" {
	# The guard denied the very command that documented it: prose naming
	# `nohup`/`&` inside a heredoc is unquoted text, so quote-scrubbing alone
	# left it exposed. Heredoc bodies are dropped before judging.
	run guard "mise run fmt; python3 - <<PY
detaching it with nohup / & loses the wake-up
PY"
	! denied "$output"
}

@test "a pager on an EARLIER command does not condemn a later mise run" {
	# The guard denied this exact shape: the `| tail -2` belongs to `git push`,
	# and `mise run verified` in a later segment carries no pager at all. Judging
	# the whole command string flagged a correct use of the recommended form.
	run guard 'git push -u origin br 2>&1 | tail -2; mise run verified'
	! denied "$output"
}

@test "a pager in the SAME segment as the mise run is still caught" {
	run guard 'git push -u origin br; mise run verify 2>&1 | tail -2'
	denied "$output"
}
