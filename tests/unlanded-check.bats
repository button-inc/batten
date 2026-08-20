#!/usr/bin/env bats
# The end-of-turn unlanded rule (CLOUD-97): report the verdict the engine already
# reached, decide nothing, and ask once per HEAD.
#
# Every case drives the gate through a STUB `batten` on `BATTEN_BIN` — the seam
# `.claude/hooks/batten-hook.sh` documents and `linear-check` already uses. That
# is not a convenience: the point of this gate is that it computes no landedness
# of its own, so a suite that had to mint a real finding would be testing the
# engine's detector rather than this file's reading of it.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/unlanded-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	rm -rf "$REPO"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet --initial-branch=work
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	printf 'x\n' >"$REPO/a.txt"
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m base
	export CLAUDE_PROJECT_DIR="$REPO"
}

# `stub <listing>` — a fake `batten` whose `state list` prints exactly `$1`.
stub() {
	local bin="$BATS_TEST_TMPDIR/batten-stub"
	{
		echo '#!/usr/bin/env bash'
		printf 'if [ "$1" = "state" ] && [ "$2" = "list" ]; then cat <<%s\n' "'EOF'"
		printf '%s\n' "$1"
		echo 'EOF'
		echo 'fi'
	} >"$bin"
	chmod +x "$bin"
	export BATTEN_BIN="$bin"
}

# The engine's own pointer shape: `<fingerprint> <rule> <ref> <count>`.
line() { printf '%s completion.unlanded refs/heads/%s %s' "${4:-abc123}" "${1:-work}" "${2:-1}"; }

@test "an unlanded finding on this ref is reported" {
	stub "$(line work 3)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unlanded: 3 commit(s)"* ]]
}

@test "the pointer names the rule and a count, and carries nothing else" {
	# Pointer, never payload (non-negotiable 4). The store line's fingerprint is
	# an internal key and the transcript it was derived from is prose; neither may
	# reach a channel the model reads.
	stub "$(line work 1 '' deadbeefcafe)"
	run "$CHECK"
	[[ "$output" == *"completion.unlanded"* ]]
	[[ "$output" != *"deadbeefcafe"* ]]
	[[ "$output" != *"refs/heads"* ]]
}

@test "another branch's finding is not this turn's" {
	# Instances key on ref, and a store is shared across every worktree of a
	# repository — so an unlanded branch somebody else is holding would otherwise
	# nag this one forever.
	stub "$(line other 2)"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a resolved finding says nothing" {
	# `Observed(0)` is how the finding self-clears when the work lands: no
	# acknowledgement from anybody, so a count of zero must read as landed.
	stub "$(line work 0)"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a rule that did not look is not a finding" {
	# `skipped`/`errored` are the engine's words for "no observation". Asking the
	# question on the strength of a scan that never ran is the false green in
	# nudge form — the same reading `Observation::NotObserved` exists to force.
	stub "$(line work skipped)"
	run "$CHECK"
	[ "$status" -eq 0 ]
	stub "$(line work errored)"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "another rule's finding is not this one" {
	stub "abc123 budget.instructions refs/heads/work 4"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "it asks once per HEAD, then goes quiet" {
	# The finding HOLDS for as long as the work is unlanded, so an unsuppressed
	# rule repeats one pointer at every turn end for the rest of a session — which
	# is how a channel stops being read.
	stub "$(line work 1)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a new commit earns a fresh pointer" {
	# A new commit is a new answer to "is this landed yet", so the receipt is keyed
	# on the HEAD sha rather than on the branch.
	stub "$(line work 1)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	printf 'more\n' >>"$REPO/a.txt"
	git -C "$REPO" commit -q -am more
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "the bypass is honoured" {
	stub "$(line work 1)"
	BATTEN_UNLANDED_CHECK_BYPASS=1 run "$CHECK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "no binary is silence, never a verdict" {
	# It runs inside a Stop hook, so no failure it can produce may be the reason a
	# turn cannot end. Every could-not-look path is exit 0.
	export BATTEN_BIN="$BATS_TEST_TMPDIR/does-not-exist"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an empty listing is silence" {
	stub ""
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a line the reader cannot parse is skipped, never judged" {
	stub "garbage without four columns"
	run "$CHECK"
	[ "$status" -eq 0 ]
}
