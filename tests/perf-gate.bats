#!/usr/bin/env bats
# subject: mise-tasks/perf-gate.sh
# The one name `verify` and CI call for the paired measurement (CLOUD-172), and
# until CLOUD-480 it had no suite at all — so the three properties its own header
# argues for were prose. Each is a decision this file pins:
#
#   * a measurement that did not complete passes its code through, and no
#     comparison is made from the wreckage
#   * a skip — `perf-pair` establishing the binary cannot have changed — is a
#     pass, not an empty stream handed to `perf-compare` as could-not-look
#   * a real regression's code reaches the caller unflattened
#
# `mise` is shimmed rather than real, and that is the subject: this task's whole
# body is the COMPOSITION of two siblings, so what it must get right is which one
# it calls with what, and each sibling's own verdict is its own suite's business.
# The shim also records the call sequence, which is the only way to assert the
# negative — that a failed producer never reaches the consumer.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/perf-gate.sh"
	BIN="$BATS_TEST_TMPDIR/bin"
	CALLS="$BATS_TEST_TMPDIR/calls"
	mkdir -p "$BIN"
	: >"$CALLS"
	PATH="$BIN:$PATH"
	export PATH CALLS
}

# `$1` = what `perf-pair` prints, `$2` = its exit code, `$3` = perf-compare's.
shim_mise() {
	cat >"$BIN/mise" <<-EOF
		#!/usr/bin/env bash
		echo "\$*" >>"\$CALLS"
		case "\$*" in
		"run perf-pair") printf '%s' '$1'; exit ${2:-0} ;;
		"run perf-compare") cat >/dev/null; exit ${3:-0} ;;
		esac
		exit 0
	EOF
	chmod +x "$BIN/mise"
}

called() { grep -qxF "$1" "$CALLS"; }

@test "a paired measurement that did not complete passes its code through" {
	shim_mise '' 2
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"did not complete"* ]]
	! called "run perf-compare"
}

@test "THE DEFECT: could-not-look is not flattened into a regression" {
	# The distinction `verify` needs in order to tell "fix your change" from "fix
	# your checkout": an unresolvable merge base is 2, a regression is 1, and a
	# gate that returned 1 for both would send an author after the wrong thing.
	shim_mise '' 2
	run "$GATE"
	[ "$status" -eq 2 ]
	[ "$status" -ne 1 ]
}

@test "a skip is a pass, never an empty stream handed to the comparison" {
	shim_mise 'perf-pair: the binary is unchanged on this branch
' 0
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to compare"* ]]
	! called "run perf-compare"
}

@test "records reach the comparison, which is the whole composition" {
	shim_mise 'arm=base path=noop p50=3.0
arm=head path=noop p50=3.0
' 0 0
	run "$GATE"
	[ "$status" -eq 0 ]
	called "run perf-compare"
}

@test "a regression's code reaches the caller" {
	shim_mise 'arm=base path=noop p50=3.0
arm=head path=noop p50=9.0
' 0 1
	run "$GATE"
	[ "$status" -eq 1 ]
	called "run perf-compare"
}

@test "the comparison's could-not-look reaches the caller too" {
	shim_mise 'arm=head path=noop p50=9.0
' 0 2
	run "$GATE"
	[ "$status" -eq 2 ]
	called "run perf-compare"
}
