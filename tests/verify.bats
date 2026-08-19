#!/usr/bin/env bats
# CLOUD-407. `verify`'s exit code is a two-valued question with one narrow
# answer: 2 means "main moved under this branch, lap and try again", and every
# other failure means "stop, something about this tree is wrong". `land` is
# hard-wired to that reading (`mise-tasks/land`, the lap-on-2 arm), so a second
# way to produce a 2 is not a cosmetic defect — it is `land` lapping to its
# backstop over a real refusal it was built to stop on.
#
# The escape route was `depends`. mise runs a dependency before the body and
# propagates its code VERBATIM, so `batten check`'s policy verdict of 2 (through
# `hooks` -> `ci`) and `tree-clean`/`semver`'s "could not look" 2 all left
# `verify` without ever passing the body's guards. Measured on PR #322: eight
# laps, ~13 minutes, three `path:line` pointers nobody surfaced.
#
# The fix is structural rather than defensive — `verify` carries no `depends` at
# all, and everything that can fail for a content reason reaches it through one
# guarded call to `verify:gated` that flattens whatever code it carried. So this
# suite asserts BOTH halves: the structure that removes the escape route, and the
# behaviour over a stubbed decision table.
#
# tests/task-fail-closed.bats is the sibling: it holds the fail-closed shape of
# both bodies. This one holds the exit-code contract.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	MAPPER=$(awk '/^\[tasks\.verify\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^.{3}$/{exit} c' mise.toml)
	GATED=$(awk '/^\[tasks\."verify:gated"\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^.{3}$/{exit} c' mise.toml)

	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	BODY_FILE="$BATS_TEST_TMPDIR/verify-body"
	printf '%s\n' "$MAPPER" >"$BODY_FILE"

	FAKE_BRANCH="work"
	FAKE_GIT_DIR="$BATS_TEST_TMPDIR/gitdir"
	mkdir -p "$FAKE_GIT_DIR/batten-receipts"
	claim_receipt CLOUD-431
}

# The stub stands in for the whole task runner. Each task's exit code is read
# from a file the case writes, so a case names only the codes it cares about and
# everything else answers 0 — the same shape `tests/land.bats` uses, for the same
# reason: the subject here is the mapping, not the tasks being mapped.
stub_mise() {
	cat >"$STUB/mise" <<-'EOF'
		#!/usr/bin/env bash
		if [ "$1" = "run" ]; then
			echo "$2" >>"$MISE_STUB_CALLS"
			rc_file="$MISE_STUB_DIR/rc.$2"
			[ -f "$rc_file" ] && exit "$(cat "$rc_file")"
		fi
		exit 0
	EOF
	chmod +x "$STUB/mise"
}

# `git` answers the three questions the mapper asks: which branch this is, where
# the git dir lives, and (inside `verify:gated`, which this suite does not run)
# a couple of rev-parses. Stubbed so no case can reach the real repository —
# without it the claim-receipt check below would read the DEVELOPER's branch and
# the developer's receipt, and the suite would pass or fail on the state of
# whatever clone it happened to run in.
stub_git() {
	cat >"$STUB/git" <<-EOF
		#!/usr/bin/env bash
		case "\$1 \$2" in
		  "symbolic-ref --quiet") echo "$FAKE_BRANCH" ;;
		  "rev-parse --git-dir")  echo "$FAKE_GIT_DIR" ;;
		  *) echo 0000000 ;;
		esac
	EOF
	chmod +x "$STUB/git"
}

# CLOUD-431: the claim receipt `verify` now demands. Present by default, because
# every case below is about the EXIT-CODE contract and would otherwise stop at a
# refusal that is not its subject.
claim_receipt() { printf '%s\n' "$1" >"$FAKE_GIT_DIR/batten-receipts/claim.$FAKE_BRANCH"; }
no_claim_receipt() { rm -f "$FAKE_GIT_DIR/batten-receipts/claim.$FAKE_BRANCH"; }
# CLOUD-693's second kind, minted by `mise run bot-issue receipt` on a bot branch.
bot_receipt() { printf '%s\n' "$1" >"$FAKE_GIT_DIR/batten-receipts/bot.$FAKE_BRANCH"; }
no_bot_receipt() { rm -f "$FAKE_GIT_DIR/batten-receipts/bot.$FAKE_BRANCH"; }

task_exits() { printf '%s\n' "$2" >"$BATS_TEST_TMPDIR/rc.$1"; }

run_verify() {
	stub_mise
	stub_git
	MISE_STUB_DIR="$BATS_TEST_TMPDIR" \
		MISE_STUB_CALLS="$BATS_TEST_TMPDIR/calls" \
		PATH="$STUB:$PATH" \
		run bash "$BODY_FILE"
}

# `grep -c` prints 0 AND exits 1 when it matches nothing, so the obvious
# `grep -c … || echo 0` emits TWO lines and every comparison against it is a
# syntax error rather than a failure. Capture, then default.
called() {
	local seen
	seen=$(grep -c "^$1\$" "$BATS_TEST_TMPDIR/calls" 2>/dev/null) || seen=0
	printf '%s\n' "$seen"
}

@test "the mapper body was found at all — this suite is not passing vacuously" {
	[ -n "$MAPPER" ]
	[[ "$MAPPER" == *"linear-check"* ]]
	[[ "$MAPPER" == *"verify:gated"* ]]
}

@test "verify declares no depends, which is the escape route CLOUD-407 closed" {
	# The load-bearing structural assertion. A `depends` on `verify` would let a
	# dependency's exit code reach a caller without passing a single guard in the
	# body below, which is the entire defect — and it would do so silently, since
	# nothing in the body would have to change for it to happen.
	local depends
	depends=$(awk '/^\[tasks\.verify\]/{f=1} f&&/^\[tasks\."verify:gated"\]/{exit} f&&/^depends = /{print}' mise.toml)
	[ -z "$depends" ] || {
		echo "verify grew a depends, so a dependency's exit code escapes unmapped: $depends"
		false
	}
}

@test "verify:gated carries the depends verify gave up" {
	local depends
	depends=$(awk '/^\[tasks\."verify:gated"\]/{f=1} f&&/^depends = /{print; exit}' mise.toml)
	[[ "$depends" == *"tree-clean"* ]]
	[[ "$depends" == *"ci"* ]]
	[[ "$depends" == *"cross-check"* ]]
}

@test "the mapper mints exactly one exit 2, and it is the behind-verdict arm" {
	# A count, not a search. Two `exit 2`s would each be defensible in isolation
	# and together would restore the collision, so the assertion has to be that
	# there is one — the same reason `tests/land.bats` counts its stops.
	local twos
	twos=$(grep -c '^[[:space:]]*exit 2[[:space:]]*$' <<<"$MAPPER")
	[ "$twos" -eq 1 ]
	# And it is reachable only from linear-check's code, never from anything else.
	[[ "$MAPPER" == *'if [ "$linear_rc" = 2 ]; then'* ]]
}

@test "verify:gated mints no exit 2 at all — a content failure is a stop" {
	local twos
	twos=$(grep -c '^[[:space:]]*exit 2[[:space:]]*$' <<<"$GATED" || true)
	[ "$twos" -eq 0 ]
}

# --- the decision table ------------------------------------------------------

@test "a clean run exits 0 and reaches the gate set" {
	run_verify
	[ "$status" -eq 0 ]
	[ "$(called linear-check)" -eq 1 ]
	[ "$(called verify:gated)" -eq 1 ]
}

@test "linear-check's behind-verdict is the one thing that exits 2" {
	task_exits linear-check 2
	run_verify
	[ "$status" -eq 2 ]
	[[ "$output" == *"main moved under this branch"* ]]
	# And it stops BEFORE spending the gate set, which is the economy the
	# reordering bought: a branch that is behind will lap regardless.
	[ "$(called verify:gated)" -eq 0 ]
}

@test "linear-check's environment refusal is a stop, not a lap" {
	task_exits linear-check 1
	run_verify
	[ "$status" -eq 1 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "A POLICY VERDICT REACHING verify IS A STOP: gated's 2 leaves as 1" {
	# The headline case. `batten check` exits 2 for a violation and reaches
	# `verify` through `hooks` -> `ci` -> `verify:gated`'s depends. Before the
	# split that 2 arrived at `land` indistinguishable from "main moved", and
	# `land` lapped on it eight times over a tree that was genuinely refused.
	task_exits verify:gated 2
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"this is not a rebase"* ]]
}

@test "a code outside the table is flattened too, not passed through" {
	# Measured in the wild: a clippy failure inside `ci` made `mise run verify`
	# exit 101. Whatever a dependency carries, it is a content failure and it
	# leaves as 1 — the mapping is over the CONDITION, never over the code.
	for code in 3 101 137 255; do
		rm -f "$BATS_TEST_TMPDIR/calls"
		task_exits verify:gated "$code"
		run_verify
		[ "$status" -eq 1 ] || {
			echo "verify:gated exiting $code left verify as $status, not 1"
			false
		}
	done
}

@test "the two conditions are told apart by the code, never by parsing prose" {
	# CLOUD-407's third acceptance clause. A fix that read `land`'s decision out
	# of a log line would pass every case above and still be the defect, so the
	# absence of that shape is asserted rather than assumed.
	[[ "$MAPPER" != *"grep"* ]]
	[[ "$MAPPER" != *"awk"* ]]
}

# --- the claim receipt (CLOUD-431) -------------------------------------------
#
# `batten hook`'s claim row is the fast feedback for this and it is a HOOK, which can be
# unloaded — today it is not even registered in `.claude/settings.json`. So the
# load-bearing half sits here, in the one task every landing path runs, and these
# cases are what make that a guarantee rather than an intention.

@test "a branch with no claim receipt cannot pass verify" {
	no_claim_receipt
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no claim receipt"* ]]
	# It stops BEFORE spending anything: the question "should this branch exist"
	# is cheaper than every question below it, and different in kind.
	[ "$(called linear-check)" -eq 0 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "the refusal names the remedy rather than only the rule" {
	no_claim_receipt
	run_verify
	[[ "$output" == *"claim-check"* ]]
	[[ "$output" == *"bot-issue receipt"* ]]
	[[ "$output" == *"No receipt written."* ]]
}

@test "A BOT RECEIPT SATISFIES IT TOO, and it is a SECOND kind rather than a wider one" {
	# CLOUD-693. Nothing on a bot branch can honestly claim "an agent read a
	# refined issue in a session that postdates the refinement" — there was no
	# session. So the bot lane mints its own receipt attesting what IS true there,
	# and `verify` accepts either. Widening the agent receipt to cover bots would
	# have made it mean less on every branch, which is what CLOUD-431 exists to
	# prevent.
	no_claim_receipt
	bot_receipt CLOUD-999
	run_verify
	[ "$status" -eq 0 ]
	[[ "$output" != *"no claim receipt"* ]]
}

@test "neither receipt is still a refusal — the pair is an OR, not an escape hatch" {
	no_claim_receipt
	no_bot_receipt
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no claim receipt"* ]]
}

@test "a detached HEAD is exempt, because a rebase detaches" {
	# The same carve-out the engine's claim row makes deliberately. Refusing here would
	# fail every lap of `land`, which detaches to rebase — a state that is not a
	# defect and that no claim receipt could describe.
	cat >"$STUB/git" <<-EOF
		#!/usr/bin/env bash
		case "\$1 \$2" in
		  "symbolic-ref --quiet") exit 1 ;;
		  "rev-parse --git-dir")  echo "$FAKE_GIT_DIR" ;;
		  *) echo 0000000 ;;
		esac
	EOF
	chmod +x "$STUB/git"
	no_claim_receipt
	# `stub_mise` explicitly, because this case cannot use `run_verify` — that
	# helper reinstalls the git stub and would undo the detached HEAD.
	stub_mise
	MISE_STUB_DIR="$BATS_TEST_TMPDIR" \
		MISE_STUB_CALLS="$BATS_TEST_TMPDIR/calls" \
		PATH="$STUB:$PATH" \
		run bash "$BODY_FILE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"no claim receipt"* ]]
}

@test "the receipt check precedes every other question in the mapper" {
	# Ordering asserted textually as well as behaviourally: a later reader moving
	# it below `linear-check` would still pass the cases above (both refuse), and
	# would quietly start paying for a fetch to answer a question that does not
	# need one.
	# Matched on the CALLS, not on prose: the body's opening comment discusses
	# linear-check several lines above any code, so grepping the bare name would
	# compare a comment against a command and always fail.
	local claim_line linear_line
	claim_line=$(grep -n 'claim_receipt=' <<<"$MAPPER" | head -1 | cut -d: -f1)
	linear_line=$(grep -n '^mise run linear-check' <<<"$MAPPER" | head -1 | cut -d: -f1)
	[ -n "$claim_line" ]
	[ "$claim_line" -lt "$linear_line" ]
}
