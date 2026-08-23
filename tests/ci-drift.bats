#!/usr/bin/env bats
# subject: mise-tasks/ci-drift.sh
# The fetching half of "agents fetch, gates decide" for the merge contract
# (CLOUD-54), and until CLOUD-480 it had no suite. Its one non-obvious property is
# the one its header argues for and nothing held it to: a fetch that could not
# look has NOT found agreement, so it is exit 1 and never a green verdict about a
# ruleset nobody read.
#
# `gh` and `cargo` are shimmed. That is the subject rather than a shortcut: this
# task's body is a fetch and a hand-off, so what it must get right is which
# endpoint it reads, that the bytes reach the decision on stdin, and that the
# decision's verdict passes through. Whether `config lint --host-rules` decides
# correctly is that command's own business, and reaching the real API would make
# this file's verdict a property of the world rather than of the commit.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ci-drift.sh"
	BIN="$BATS_TEST_TMPDIR/bin"
	SEEN="$BATS_TEST_TMPDIR/seen"
	STDIN="$BATS_TEST_TMPDIR/stdin"
	mkdir -p "$BIN"
	: >"$SEEN"
	PATH="$BIN:$PATH"
	export PATH SEEN STDIN
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# `$1` = what the ruleset endpoint returns, `$2` = its exit code.
shim_gh() {
	cat >"$BIN/gh" <<-EOF
		#!/usr/bin/env bash
		echo "\$*" >>"\$SEEN"
		case "\$1" in
		repo) echo "acme/widget" ;;
		api) printf '%s' '$1'; exit ${2:-0} ;;
		esac
	EOF
	chmod +x "$BIN/gh"
}

# `$1` = the linter's exit code.
shim_cargo() {
	cat >"$BIN/cargo" <<-EOF
		#!/usr/bin/env bash
		echo "cargo \$*" >>"\$SEEN"
		cat >"\$STDIN"
		exit ${1:-0}
	EOF
	chmod +x "$BIN/cargo"
}

@test "THE DEFECT: a fetch that could not look is exit 1, never a green verdict" {
	shim_gh '' 1
	shim_cargo 0
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not look has not found agreement"* ]]
}

@test "a failed fetch hands nothing to the decision" {
	shim_gh '' 1
	shim_cargo 0
	run "$GATE"
	[ "$status" -eq 1 ]
	! grep -q '^cargo ' "$SEEN"
}

@test "the fetched bytes reach the decision on stdin, unaltered" {
	shim_gh '{"rules":[{"type":"required_status_checks"}]}' 0
	shim_cargo 0
	run "$GATE"
	[ "$status" -eq 0 ]
	[ "$(cat "$STDIN")" = '{"rules":[{"type":"required_status_checks"}]}' ]
}

@test "the decision is the offline one, over stdin — the gate spawns no second fetch" {
	shim_gh '{"rules":[]}' 0
	shim_cargo 0
	run "$GATE"
	[ "$status" -eq 0 ]
	grep -q 'config lint --host-rules -' "$SEEN"
}

@test "the decision's verdict passes through, so drift fails the gate" {
	shim_gh '{"rules":[]}' 0
	shim_cargo 1
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "the branch is the one CI_DRIFT_BRANCH names, and main is the default" {
	shim_gh '{"rules":[]}' 0
	shim_cargo 0
	run "$GATE"
	grep -q 'rules/branches/main' "$SEEN"

	: >"$SEEN"
	CI_DRIFT_BRANCH=release run "$GATE"
	grep -q 'rules/branches/release' "$SEEN"
}
