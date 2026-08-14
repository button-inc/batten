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

# `git` is called only for the two rev-parses inside `verify:gated`, which this
# suite never runs; the mapper needs none. Stubbed anyway so a case that grows
# one cannot silently reach the real repository.
stub_git() {
	printf '%s\n' '#!/usr/bin/env bash' 'echo 0000000' >"$STUB/git"
	chmod +x "$STUB/git"
}

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
