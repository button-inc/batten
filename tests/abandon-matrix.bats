#!/usr/bin/env bats
# subject: mise-tasks/abandon-matrix.sh
# abandon-matrix: stop paying for a matrix whose verdict is already in
# (CLOUD-900).
#
# Everything here runs through a stubbed `gh`. The task's only inputs are one
# list and one POST per run, so a stub that scripts those two covers every row
# without a remote, a runner or a clock.
#
# THE PROPERTY THAT OUTRANKS EVERY ROW, and the reason each case asserts status
# 0 including the failures: this is called from `land`'s red arm, one line before
# a `die` that names the real failure. A non-zero exit here would replace a
# diagnosable test failure with a confusing one about a cleanup step, so there is
# no input for which stopping is the right answer.
#
# THE ROW THAT MATTERS MOST is the fan-in exclusion. Cancelling the run carrying
# `final` leaves the one context branch protection requires ungraded, and
# `checks-green` reads a cancelled required check as "no answer" (CLOUD-363) — so
# that single mistake converts a saving into a branch that can never land.

setup() {
	ABANDON="$BATS_TEST_DIRNAME/../mise-tasks/abandon-matrix.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	# Hermetic for `tests/ci-lease-precondition.bats`'s reason: these names have
	# ambient fallbacks that CI sets and a developer box does not, so a case that
	# reaches "unset" by unsetting one variable would behave differently under
	# Actions — a verify/CI disagreement by construction.
	unset ABANDON_SHA SHA GH_REPO

	export REPO=button-inc/batten
	export GH_TOKEN=ghs-not-a-real-token
	# The declaration under test. It arrives from mise.toml [env] in production;
	# naming it here keeps each case's subject local, and `ci-local-parity`
	# property 17 is what holds the real value to the real workflow.
	export CI_FANIN_WORKFLOW=.github/workflows/ci.yml

	# A healthy in-flight matrix: four runs, one of which carries the fan-in.
	# Each case moves exactly one thing, so a failure names the row rather than
	# the fixture.
	runs_are \
		'11	.github/workflows/ci.yml' \
		'22	.github/workflows/rust.yml' \
		'33	.github/workflows/test.yml' \
		'44	.github/workflows/zizmor.yml'
	stub_gh
}

# The `id<TAB>path` lines the stub's `--jq` filter would have produced.
runs_are() { printf '%s\n' "$@" >"$BATS_TEST_TMPDIR/runs"; }

stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
t="$BATS_TEST_TMPDIR"
url=""
for a in "\$@"; do case "\$a" in repos/*) url="\$a"; break ;; esac; done
case "\$url" in
  */cancel)
    [ ! -e "\$t/cancel-refused" ] || exit 1
    echo "\$url" >>"\$t/cancels" ;;
  *actions/runs\?head_sha=*)
    [ ! -e "\$t/list-refused" ] || exit 1
    cat "\$t/runs" ;;
  *) exit 1 ;;
esac
EOF
	chmod +x "$STUB/gh"
}

cancels() { cat "$BATS_TEST_TMPDIR/cancels" 2>/dev/null || true; }
cancel_count() { cancels | grep -c . || true; }

@test "the siblings are cancelled and the fan-in's run is spared — the acceptance case" {
	run "$ABANDON" cafebabecafebabe "ci failure"
	[ "$status" -eq 0 ]
	# Three cancelled, and the fan-in's run is not among them.
	[ "$(cancel_count)" -eq 3 ]
	cancels | grep -q 'runs/22/cancel'
	cancels | grep -q 'runs/33/cancel'
	cancels | grep -q 'runs/44/cancel'
	! cancels | grep -q 'runs/11/cancel'
}

@test "THE ROW THAT MATTERS: the run carrying the fan-in is never cancelled" {
	# Stated as its own case rather than left to the assertion above, because
	# this is the one mistake that turns a saving into a branch that cannot land:
	# a cancelled `final` is not an answer (CLOUD-363), so `ci-wait` would poll a
	# head whose verdict can never arrive.
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	! cancels | grep -q 'runs/11/cancel'
	[[ "$output" == *"sparing run 11"* ]]
	[[ "$output" == *"wedges the landing"* ]]
}

@test "a fan-in declared for a file no run carries spares nothing — and still cancels the rest" {
	# The drift case. `ci-local-parity` property 17 is what stops it reaching
	# production; this records what the task does if it ever does.
	export CI_FANIN_WORKFLOW=.github/workflows/moved-elsewhere.yml
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	[ "$(cancel_count)" -eq 4 ]
}

@test "an unset fan-in declaration cancels NOTHING rather than guessing" {
	# Fail closed on the one input whose absence is unrecoverable: with no
	# fan-in named, every candidate looks cancellable and the wedge is one API
	# call away. Doing nothing costs the minutes this task exists to save, which
	# is the strictly cheaper mistake.
	unset CI_FANIN_WORKFLOW
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	[ "$(cancel_count)" -eq 0 ]
	[[ "$output" == *"CI_FANIN_WORKFLOW is unset"* ]]
	[[ "$output" == *"nothing cancelled"* ]]
}

@test "a refused cancellation is a pointer, not a stop — and the rest still go" {
	touch "$BATS_TEST_TMPDIR/cancel-refused"
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	[[ "$output" == *"cancellation refused"* ]]
	[[ "$output" == *"it bills out"* ]]
}

@test "a list that will not answer stops without cancelling and without failing" {
	touch "$BATS_TEST_TMPDIR/list-refused"
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	[ "$(cancel_count)" -eq 0 ]
	[[ "$output" == *"could not list the runs"* ]]
}

@test "nothing in flight is a clean no-op" {
	runs_are ''
	run "$ABANDON" cafebabecafebabe
	[ "$status" -eq 0 ]
	[ "$(cancel_count)" -eq 0 ]
	[[ "$output" == *"nothing still in flight"* ]]
}

@test "a run that has already completed is not asked to cancel" {
	# The filter is the stub's, mirroring the `--jq` the task passes: a completed
	# run never reaches the loop. Asserted so a later edit that drops
	# `select(.status != \"completed\")` from the query is caught here rather
	# than as an unexplained API call count in production.
	grep -q 'select(.status != "completed")' "$ABANDON"
}

@test "the reason is carried into the pointer, and the SHA is abbreviated" {
	run "$ABANDON" cafebabecafebabe "windows failure"
	[ "$status" -eq 0 ]
	[[ "$output" == *"windows failure"* ]]
	[[ "$output" == *"cafebabe"* ]]
	# Pointer-only (non-negotiable rule 4): a run id and a workflow path, never
	# a line from the run being stopped.
	[[ "$output" == *".github/workflows/rust.yml"* ]]
}

@test "no SHA anywhere is a give-up rather than a guess at HEAD's neighbours" {
	# Outside any repository, so the `git rev-parse HEAD` fallback has nothing to
	# answer with either. `GIT_CEILING_DIRECTORIES` rather than a bare `cd`: the
	# temp dir can sit under a checkout on some boxes, and a case whose subject
	# is "no SHA" must not depend on where the suite happens to run.
	cd "$BATS_TEST_TMPDIR"
	export GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR"
	run env -u GIT_DIR "$ABANDON"
	[ "$status" -eq 0 ]
	[ "$(cancel_count)" -eq 0 ]
}
