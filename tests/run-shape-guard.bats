#!/usr/bin/env bats
# Shapes that report success while destroying what the harness reads: a pager or
# filter eating the exit status, a trailing list element replacing it, and
# nohup/& orphaning the process. All of them fail GREEN, which is why noticing
# them did not stop them.
#
# CLOUD-199 generalised the matcher. It used to be scoped to the literal string
# `mise run`, and an agent complying with it exactly kept making the same error
# on the next command — measured on `git push`, `cargo clippy` and `cargo test`
# in the same sessions. A pipe replaces the exit status; that is a property of
# pipes, not of `mise`.

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

# --- piped-verdict: the original mise-run cases ------------------------------

@test "the shape that reported green over a failed verify is denied" {
	run guard 'mise run verify 2>&1 | tail -6'
	denied "$output"
	[[ "$output" == *"exit status"* ]]
}

@test "head masks the status exactly as tail does" {
	run guard 'mise run ci 2>&1 | head -20'
	denied "$output"
}

@test "the denial states the principle and the compliant form" {
	# Naming one command is how the second instance happened: the agent complied
	# with the literal wording and made the same error on `git push`.
	run guard 'mise run test:bats | tail -5'
	[[ "$output" == *"exit status"* ]]
	[[ "$output" == *"run_in_background"* ]]
	# The compliant form is the command ALONE in the call.
	[[ "$output" == *"alone"* ]]
}

# --- piped-verdict: every other verdict-bearing command (CLOUD-199) ----------

@test "THE MEASURED CASE: git push piped to tail is denied" {
	# Re-run in the correct form, that same push returned exit 1 (`stale info` —
	# the branch had been merged and deleted), which the piped form reported as
	# success.
	run guard 'git push -u origin br 2>&1 | tail -2'
	denied "$output"
}

@test "git fetch and git rebase are verdict-bearing too" {
	run guard 'git fetch origin main | tail -1'
	denied "$output"
	run guard 'git rebase origin/main 2>&1 | tail -20'
	denied "$output"
}

@test "a filter is the same substitution as a pager" {
	# The ANSI case: cargo colours its diagnostics, so every line starts with an
	# escape sequence and `^error` cannot match at line start. The filter was
	# structurally incapable of finding what it searched for, and emptiness was
	# read as absence of errors.
	run guard "cargo clippy -q -p batten --all-targets --all-features -- -D warnings 2>&1 | grep -E '^error|warning:' | head -5"
	denied "$output"
}

@test "wc and awk are filters for the same reason" {
	run guard 'cargo build 2>&1 | wc -l'
	denied "$output"
	run guard "git push origin br 2>&1 | awk '/rejected/'"
	denied "$output"
}

@test "THE PER-BINARY CASE: a cargo test tail window is itself a green verdict" {
	# Sharper than a truncated verdict. `cargo test` emits one `test result:` per
	# test BINARY, so a tail window shows the last few binaries' complete,
	# genuinely green blocks — a failing test in an earlier binary has scrolled
	# past and there is nothing in the visible text to notice. Every other
	# instance left a tell; this one presents a fully-formed pass.
	run guard 'cargo test -p batten --quiet 2>&1 | tail -30'
	denied "$output"
}

@test "a mutating gh pr call is verdict-bearing" {
	run guard 'gh pr create --draft --title x --body y | tail -1'
	denied "$output"
}

# --- trailing list (CLOUD-199) ----------------------------------------------

@test "THE LAUNDERED SHAPE: a trailing echo replaces the status" {
	# No pipe involved, and it was the form this guard's own CORRECT string and
	# the toolchain memory both prescribed. Backgrounded it is worse than a
	# misread: the task-completion notification carries the compound's status, so
	# a failed task arrives as `completed (exit code 0)` — an authoritative
	# statement from the harness. Measured twice in one session.
	run guard 'mise run verify >/tmp/v.log 2>&1; echo "EXIT=$?"'
	denied "$output"
	[[ "$output" == *"alone"* ]]
}

@test "the trailing list is denied whatever follows, not just an echo" {
	run guard 'cargo test >/tmp/t.log 2>&1; tail -20 /tmp/t.log'
	denied "$output"
	run guard 'git push -u origin br >/tmp/p.log 2>&1; git status'
	denied "$output"
}

@test "|| masks the status the same way ; does" {
	# `a || b` runs b BECAUSE a failed, and exits with b's status — so a failure
	# is converted into a success by construction.
	run guard 'mise run ci >/tmp/ci.log 2>&1 || echo failed'
	denied "$output"
}

@test "&& is NOT denied, because it cannot manufacture a green" {
	# The one place this guard departs from CLOUD-199's written acceptance, and
	# deliberately. `a && b` short-circuits: when `a` fails, `b` never runs and
	# the list exits with `a`'s non-zero status. There is no false green to stop,
	# so denying it would be a pure false positive — and a guard with false
	# positives gets bypassed, which is this issue's own argument. `;` and `||`
	# both genuinely discard the verdict and both are denied above.
	run guard 'mise run linear-check && mise run commit-lint'
	! denied "$output"
	run guard 'mise run verify >/tmp/v.log 2>&1 && mise run verified'
	! denied "$output"
}

@test "a verdict-bearing command alone in the call is the compliant form" {
	run guard 'mise run verify >/tmp/v.log 2>&1'
	! denied "$output"
	run guard 'cargo test -p batten'
	! denied "$output"
	run guard 'git push -u origin br'
	! denied "$output"
}

# --- what stays allowed ------------------------------------------------------

@test "a pager over a file is fine — it is a pager over a live task that is not" {
	run guard 'tail -20 /tmp/v.log'
	! denied "$output"
	run guard 'grep -n EXIT /tmp/v.log'
	! denied "$output"
}

@test "a read-only query is not verdict-bearing" {
	run guard 'git log --oneline | head -5'
	! denied "$output"
	run guard 'gh pr view --json state | jq -r .state'
	! denied "$output"
	run guard 'cargo metadata --format-version 1 | jq -r .workspace_root'
	! denied "$output"
	run guard 'git status --short; git log --oneline -3'
	! denied "$output"
}

@test "jq is composition, not a verdict substitute" {
	# graph-check's documented interface IS its stdout JSON, and jq is not in the
	# filter set the issue enumerates. Widening to every pipe would deny ordinary
	# composition, which is the false-positive rate that gets a guard bypassed.
	run guard 'mise run graph-check | jq -r .ready'
	! denied "$output"
}

@test "mise exec runs a program directly; only the wrapped program is judged" {
	run guard 'mise exec -- git log --oneline | tail -3'
	! denied "$output"
	# ... and the wrapper does not hide a verdict-bearing one.
	run guard 'mise exec -- cargo test -p batten | tail -3'
	denied "$output"
}

# --- bats is verdict-bearing (CLOUD-473) -------------------------------------
#
# THE REGRESSION: this file's own wrapper test used `mise exec -- bats
# tests/foo.bats | tail -3` as its ALLOWED example, so the omission was not
# merely uncovered — it was asserted. `bats` is how every shell gate in this
# repo is decided, and the `mise` row covered exactly one of its three
# spellings: `mise run test:bats` was guarded while `mise exec -- bats …` (the
# web sandbox's working form) and a path-invoked `tests/bats/bin/bats` were not.
# Measured on this repo: a suite piped to `tail` reported green over three
# failures, one of them a hang.

@test "THE MEASURED CASE: a bats suite piped to tail is denied" {
	run guard './tests/bats/bin/bats tests/land.bats 2>&1 | tail -20'
	denied "$output"
	[[ "$output" == *"exit status"* ]]
}

@test "the wrapper spellings of bats are denied too" {
	run guard 'mise exec -- bats tests/land.bats | tail -3'
	denied "$output"
	run guard 'bats tests/land-lock.bats >/tmp/b.log 2>&1; grep -c "^not ok" /tmp/b.log'
	denied "$output"
}

@test "bats without a suite answers nothing, so it is not a verdict" {
	# The argument is what makes the run a verdict. Usage output is a query, and
	# denying a pipe over it would be a pure false positive.
	run guard 'bats --version | head -1'
	! denied "$output"
	run guard 'bats --help | grep jobs'
	! denied "$output"
}

@test "a bats run alone in the call is the compliant form" {
	run guard 'mise exec -- bats --jobs 4 tests/land.bats >/tmp/b.log 2>&1'
	! denied "$output"
}

@test "a commit message describing the shape is not the shape" {
	run guard 'git commit -m "explain why mise run verify | tail hides the exit code"'
	! denied "$output"
	run guard 'git commit -m "cargo test | tail -30 reported green over a failing binary"'
	! denied "$output"
}

@test "a heredoc body describing the shapes is not the shape" {
	# The guard denied the very command that documented it: prose naming
	# `nohup`/`&` inside a heredoc is unquoted text, so quote-scrubbing alone
	# left it exposed. Heredoc bodies are dropped before judging.
	run guard "mise run fmt; python3 - <<PY
detaching it with nohup / & loses the wake-up
PY"
	# Still denied — but for the TRAILING LIST, not for the heredoc prose.
	denied "$output"
	run guard "cat > /tmp/notes.md <<PY
never run: cargo test | tail -30, it reports green over a failing binary
PY"
	! denied "$output"
}

@test "a pager on a read-only EARLIER command does not condemn a later one" {
	# Per segment, not per command string. The original bug denied a correct
	# command because a pager attached to the FIRST segment was read as
	# condemning the third.
	run guard 'git log --oneline | head -3'
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

@test "detaching a non-mise verdict-bearing command is the same defect" {
	run guard 'nohup cargo test -p batten >/tmp/t.log 2>&1 &'
	denied "$output"
}

# --- failure posture --------------------------------------------------------

@test "the bypass is honoured" {
	BATTEN_RUN_SHAPE_BYPASS=1 run guard 'mise run verify | tail -1'
	! denied "$output"
	BATTEN_RUN_SHAPE_BYPASS=1 run guard 'git push origin br | tail -1'
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
