#!/usr/bin/env bats
# `claim-race-check`'s decision table (CLOUD-446, half two).
#
# This is `tests/issue-guard.bats`' duplicate-claim corpus, re-aimed at the gate
# that now carries the predicate. The naming half went to the engine as a
# `requires_key` shape row and is covered by `crates/batten/tests/issue_key.rs`;
# between the two, nothing the retired guard decided is decided by nothing.
#
# THE ALLOWS CARRY THE RISK, and every one of them is a way this gate can become
# the reason a correct branch cannot be verified. It runs inside `verify`, so a
# false red costs the whole pre-flight rather than one tool call — a stricter
# posture than the hook it replaces, not a looser one. Hence: no `gh`, no
# network, no resolvable claim, our own PR, and a competitor that merely CITES
# the key must all pass.
#
# Driven against a stubbed `gh`, because the real answer depends on what is open
# on GitHub right now — a suite that asked the live API would pass or fail on
# the state of the board rather than on the gate's logic.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/claim-race-check"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	git -C "$ROOT" init -q
	git -C "$ROOT" config user.email dev@example.com
	git -C "$ROOT" config user.name Dev
	git -C "$ROOT" commit -q --allow-empty -m "chore: base"
	git -C "$ROOT" checkout -q -b user/cloud-49-the-work

	# Defaults: this branch has no PR of its own, and nothing else is open.
	echo "" >"$BATS_TEST_TMPDIR/self"
	echo "" >"$BATS_TEST_TMPDIR/others"
	echo "" >"$BATS_TEST_TMPDIR/their-branch"
	echo "" >"$BATS_TEST_TMPDIR/their-title"
	echo "" >"$BATS_TEST_TMPDIR/their-body"
	stub_gh
}

# A `gh` whose behaviour is set by sentinel files rather than by flags, so a case
# states only what it changes:
#   self          JSON for `gh pr view` with no number — this branch's own PR
#   others        lines of "<number> <headRefName>" for `gh pr list`
#   their-branch  the competitor's head branch
#   their-title   the competitor's title
#   their-body    the competitor's body
stub_gh() {
	cat >"$STUB/gh" <<'SH'
#!/usr/bin/env bash
tmp="$BATS_TEST_TMPDIR"
case "$1 $2" in
"pr view")
	# `gh pr view --json …` with no number is THIS branch's PR; with a number it
	# is a competitor's. The argument shape is what tells them apart.
	if [[ "$3" == --json ]]; then
		cat "$tmp/self"
		exit 0
	fi
	case "$*" in
	*"--jq .title"*) cat "$tmp/their-title" ;;
	*"--jq .body"*) cat "$tmp/their-body" ;;
	*commits*) echo "" ;;
	esac
	exit 0
	;;
"pr list")
	while read -r line; do
		[ -n "$line" ] || continue
		set -- $line
		printf '%s %s\n' "$1" "$2"
	done <"$tmp/others"
	exit 0
	;;
esac
exit 0
SH
	chmod +x "$STUB/gh"
}

# Every case runs with the fixture repo as cwd, because the gate derives the
# branch from wherever it is invoked.
run_check() {
	run bash -c "cd '$ROOT' && '$CHECK'"
}

@test "a key claimed by a different open PR is refused" {
	# The CLOUD-49 case, which is why this predicate exists: two sessions on one
	# issue, the second having read the board while it was still Todo.
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	run_check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49"* ]]
	[[ "$output" == *"#306"* ]]
}

@test "POINTER, NEVER PAYLOAD: the refusal carries no title or body" {
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	echo "feat: the secret internal codename (CLOUD-49)" >"$BATS_TEST_TMPDIR/their-title"
	echo "a body nobody else should read" >"$BATS_TEST_TMPDIR/their-body"
	run_check
	[ "$status" -eq 1 ]
	[[ "$output" != *"codename"* ]]
	[[ "$output" != *"nobody else should read"* ]]
}

@test "a competitor that merely CITES the key is allowed — CLOUD-378" {
	# The narrowing applied to BOTH sides. PR #306 named CLOUD-133 in one row of
	# an evidence table and refused CLOUD-133's own PR; a body is evidence, and
	# counts only through a closing keyword.
	echo "306 user/cloud-268-attribution" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-268-attribution" >"$BATS_TEST_TMPDIR/their-branch"
	echo "docs(agents): the attribution decision record (CLOUD-268)" >"$BATS_TEST_TMPDIR/their-title"
	echo "Prior measurement in CLOUD-49 said otherwise." >"$BATS_TEST_TMPDIR/their-body"
	run_check
	[ "$status" -eq 0 ]
}

@test "our own PR is not a competitor" {
	# Otherwise every verify on a branch that has published would refuse itself.
	echo '{"number":471,"body":""}' >"$BATS_TEST_TMPDIR/self"
	echo "471 user/cloud-49-the-work" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-the-work" >"$BATS_TEST_TMPDIR/their-branch"
	run_check
	[ "$status" -eq 0 ]
}

@test "a branch claiming nothing is not judged" {
	# `claimed-keys` answers empty rather than guessing, and a gate that guesses
	# is one that blocks correct work.
	git -C "$ROOT" checkout -q -b just-a-slug
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	run_check
	[ "$status" -eq 0 ]
	[[ "$output" == *"claims no issue"* ]]
}

@test "no gh at all is could-not-look, never a verdict" {
	# ABSENCE IS CONSTRUCTED, NOT ASSUMED. Deleting the stub falls through to
	# mise's pinned `gh`, and narrowing to `/usr/bin:/bin` only works where that
	# happens to carry none — measured: it does here and does NOT on a GitHub
	# runner, where `gh` is in `/usr/bin` and this case silently asserted
	# nothing. So the PATH is built from exactly the two programs the gate needs
	# before it asks for `gh`: `dirname`, for its own directory, and `git`, for
	# the checkout test. Anything the gate reaches for after that point is
	# unreachable by construction, which is the whole condition under test.
	local only="$BATS_TEST_TMPDIR/no-gh"
	mkdir -p "$only"
	# `bash` too: the gate's `#!/usr/bin/env bash` shebang resolves the
	# interpreter through PATH, so a dir without it is exit 127 rather than the
	# condition under test.
	ln -s "$(command -v bash)" "$only/bash"
	ln -s "$(command -v git)" "$only/git"
	ln -s "$(command -v dirname)" "$only/dirname"
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	run env -i PATH="$only" HOME="$HOME" bash -c "cd '$ROOT' && '$CHECK'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"could not look"* ]]
}

@test "a gh that fails is could-not-look too" {
	# A timeout, a 403, an unparseable response — the gate must not turn any of
	# them into a claim about the board.
	cat >"$STUB/gh" <<'SH'
#!/usr/bin/env bash
exit 1
SH
	chmod +x "$STUB/gh"
	run_check
	[ "$status" -eq 0 ]
}

@test "outside a checkout there is nothing to judge" {
	run bash -c "cd '$BATS_TEST_TMPDIR' && '$CHECK'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not a git repository"* ]]
}

@test "a body closing a DIFFERENT key overrides the branch name" {
	# `claimed-keys`' precedence: a closing keyword in this PR's own body beats
	# the branch, which is the escape hatch for a branch whose name no longer
	# reflects the work. So the race is judged on CLOUD-9, not CLOUD-49.
	printf '{"number":471,"body":"Closes CLOUD-9"}\n' >"$BATS_TEST_TMPDIR/self"
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	run_check
	[ "$status" -eq 0 ]
}

@test "CLOUD-4 does not match CLOUD-49" {
	# Exact line match on both sides, so no substring rule is needed.
	git -C "$ROOT" checkout -q -b user/cloud-4-a-different-issue
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	run_check
	[ "$status" -eq 0 ]
}

@test "the bypass is honoured and is a decision, not a shortcut" {
	echo "306 user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/others"
	echo "user/cloud-49-someone-else" >"$BATS_TEST_TMPDIR/their-branch"
	run bash -c "cd '$ROOT' && BATTEN_CLAIM_RACE_BYPASS=1 '$CHECK'"
	[ "$status" -eq 0 ]
}
