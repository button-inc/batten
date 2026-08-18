#!/usr/bin/env bats
# The decision table for `mise run semver` (CLOUD-102).
#
# The gate's subject — "does the API delta match the bump release-plz will
# infer" — is answered by cargo-semver-checks, which takes ~7s warm and needs a
# newer toolchain than this repo pins. So the suite drives a STUB: what is being
# tested here is the decision the task makes around the tool, which is where
# every one of its failure modes lives. The tool's own correctness is upstream's
# suite, and the real tool against the real crate runs in `verify` and in CI.
#
# The case this suite exists for is `a report that graded nothing is refused`.
# The invocation CLOUD-102 specifies produces exactly that shape — 0 checks, 254
# skipped, "no semver update required" — and reporting it green is how this gate
# would certify nothing forever. It is not hypothetical: the first version of
# the task inherited `CARGO_TERM_COLOR=always` from mise.toml, so its anchored
# pattern could never match the coloured summary line, and the refusal below
# silently did not fire (the CLOUD-199 defect, in a gate written to prevent the
# same class one layer up). The probe caught it; this case keeps it caught.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/semver"
	REPO="$BATS_TEST_TMPDIR/repo"
	BIN="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$REPO" "$BIN"

	# A repository with a baseline and one commit on top of it, so the
	# declared-break walk has a real range to read.
	git -C "$REPO" init -q -b main
	git -C "$REPO" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "chore: baseline"
	git -C "$REPO" branch -f baseline

	# `cargo` is what the task invokes; the stub answers for `semver-checks`.
	# Whatever the test wrote into $BATS_TEST_TMPDIR/report is echoed, and
	# $BATS_TEST_TMPDIR/rc is the exit code — so a case states the tool's
	# behaviour as data rather than by mocking a flag at a time.
	cat >"$BIN/cargo" <<-'STUB'
		#!/usr/bin/env bash
		cat "$STUB_REPORT" 2>/dev/null
		exit "$(cat "$STUB_RC" 2>/dev/null || echo 0)"
	STUB
	chmod +x "$BIN/cargo"

	cat >"$BIN/rustup" <<-'STUB'
		#!/usr/bin/env bash
		[ "$1" = "toolchain" ] && [ "$2" = "list" ] && echo stable
		exit 0
	STUB
	chmod +x "$BIN/rustup"

	cat >"$BIN/cargo-semver-checks" <<-'STUB'
		#!/usr/bin/env bash
		exit 0
	STUB
	chmod +x "$BIN/cargo-semver-checks"

	# The toolchain the comparison runs under is derived from the compiler on
	# PATH (CLOUD-593), so it is part of the stub environment rather than
	# something a case reaches out of the sandbox for.
	cat >"$BIN/rustc" <<-'STUB'
		#!/usr/bin/env bash
		echo "rustc 1.97.1 (8bab26f4f 2026-07-14)"
	STUB
	chmod +x "$BIN/rustc"

	export STUB_REPORT="$BATS_TEST_TMPDIR/report"
	export STUB_RC="$BATS_TEST_TMPDIR/rc"
	export SEMVER_ROOT="$REPO"
	export SEMVER_BASELINE="baseline"
	export PATH="$BIN:$PATH"
	: >"$STUB_REPORT"
	echo 0 >"$STUB_RC"
}

# The tool's summary line for a run that graded `n` checks.
graded() {
	printf '     Checked [   0.106s] %s checks: %s pass, 31 skip\n' "$1" "$1" >"$STUB_REPORT"
}

# A commit on top of the baseline, so the range the task walks is non-empty.
commit_with() {
	git -C "$REPO" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "$1"
}

@test "a patch-compatible delta passes, and names the claim it verified" {
	graded 223
	commit_with "fix(x): a compatible change"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"patch-compatible"* ]]
}

@test "THE VACUOUS RUN: a report that graded 0 checks is exit 2, never a pass" {
	# The shape the issue's own invocation produces. Exit 0 from the tool AND a
	# reassuring summary, so only the check count distinguishes it from a real
	# pass — which is why the count is what the gate reads.
	graded 0
	commit_with "fix(x): a change nothing graded"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"0 checks"* ]]
}

@test "an undeclared break fails, and names the lint rather than the payload" {
	graded 223
	printf -- '--- failure enum_marked_non_exhaustive: enum marked #[non_exhaustive] ---\n' >>"$STUB_REPORT"
	echo 100 >"$STUB_RC"
	commit_with "fix(x): quietly breaking"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"enum_marked_non_exhaustive"* ]]
	[[ "$output" == *"no commit declares it"* ]]
}

@test "a break declared with a bang passes, and names the declaring commit" {
	graded 223
	printf -- '--- failure enum_marked_non_exhaustive: enum marked #[non_exhaustive] ---\n' >>"$STUB_REPORT"
	echo 100 >"$STUB_RC"
	commit_with "feat(x)!: a declared break"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"DECLARED"* ]]
}

@test "a break declared with a BREAKING CHANGE footer passes too" {
	# Conventional Commits spells it two ways and the gate must read both, or an
	# author who used the footer is told to use the bang they already meant.
	graded 223
	printf -- '--- failure enum_marked_non_exhaustive: enum marked #[non_exhaustive] ---\n' >>"$STUB_REPORT"
	echo 100 >"$STUB_RC"
	commit_with "feat(x): a declared break

BREAKING CHANGE: the enum is now non_exhaustive"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"DECLARED"* ]]
}

@test "A DECLARATION ON THE BASELINE DOES NOT COUNT — only this branch's commits" {
	# The range is BASE..HEAD for the same reason commit-lint's is: a `!` that
	# landed long ago is not this branch declaring anything, and reading the
	# whole history would let any past break license every future one.
	graded 223
	printf -- '--- failure enum_marked_non_exhaustive: enum marked #[non_exhaustive] ---\n' >>"$STUB_REPORT"
	echo 100 >"$STUB_RC"
	git -C "$REPO" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "feat(x)!: an OLD declared break"
	git -C "$REPO" branch -f baseline
	commit_with "fix(x): quietly breaking, on top of it"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no commit declares it"* ]]
}

@test "an exit code that is neither verdict is exit 2 — a broken run is not a pass" {
	# A missing baseline ref, a crate that would not build, a crashed tool. The
	# tool answers 0 or 100; anything else means the comparison never completed,
	# and calling that green is the failure this whole gate is about.
	graded 223
	echo 1 >"$STUB_RC"
	commit_with "fix(x): a change"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"neither verdict"* ]]
}

@test "a missing cargo-semver-checks is exit 2, never a silent pass" {
	# PATH narrowed to the stub dir plus the system ones: the real tool is
	# installed by mise for `verify`, so leaving the ambient PATH in place would
	# find it and this case would assert nothing.
	rm "$BIN/cargo-semver-checks"
	graded 223
	PATH="$BIN:/usr/bin:/bin" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not on PATH"* ]]
}

@test "output is a pointer — lint ids and a short sha, never the rustdoc it read" {
	graded 223
	printf -- '--- failure enum_marked_non_exhaustive: enum marked #[non_exhaustive] ---\n' >>"$STUB_REPORT"
	printf 'SECRET_RUSTDOC_PAYLOAD\n' >>"$STUB_REPORT"
	echo 100 >"$STUB_RC"
	commit_with "fix(x): quietly breaking"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"SECRET_RUSTDOC_PAYLOAD"* ]]
}

# --- the toolchain the comparison runs under (CLOUD-593, CLOUD-654) -----------
#
# It used to default to a floating rustup `stable`, on the premise that the
# pinned toolchain was too old for cargo-semver-checks. CLOUD-593 coupled the
# floor to the pin and inverted that: with `rust-version` at 1.97, a `stable`
# channel resolving 1.94.1 aborts the run with "requires rustc 1.97", exit 101 —
# "could not look", which `verify` correctly refuses. These rows hold the gate to
# asking the compiler that is actually on PATH.

@test "the toolchain defaults to the one on PATH, not to a floating channel" {
	# A version no channel would produce, so a pass cannot come from the ambient
	# toolchain happening to match.
	cat >"$BIN/rustc" <<-'STUB'
		#!/usr/bin/env bash
		echo "rustc 9.9.9 (deadbeef 2026-01-01)"
	STUB
	chmod +x "$BIN/rustc"
	# The stub cargo records the toolchain selector it was invoked with.
	cat >"$BIN/cargo" <<-'STUB'
		#!/usr/bin/env bash
		echo "$1" >"$STUB_SELECTOR"
		cat "$STUB_REPORT" 2>/dev/null
		exit "$(cat "$STUB_RC" 2>/dev/null || echo 0)"
	STUB
	chmod +x "$BIN/cargo"
	export STUB_SELECTOR="$BATS_TEST_TMPDIR/selector"
	graded 223
	commit_with "fix(x): a compatible change"
	run "$GATE"
	[ "$status" -eq 0 ]
	[ "$(cat "$STUB_SELECTOR")" = "+9.9.9" ]
}

@test "SEMVER_TOOLCHAIN still overrides, so the suite can drive another claim" {
	cat >"$BIN/cargo" <<-'STUB'
		#!/usr/bin/env bash
		echo "$1" >"$STUB_SELECTOR"
		cat "$STUB_REPORT" 2>/dev/null
		exit "$(cat "$STUB_RC" 2>/dev/null || echo 0)"
	STUB
	chmod +x "$BIN/cargo"
	export STUB_SELECTOR="$BATS_TEST_TMPDIR/selector"
	graded 223
	commit_with "fix(x): a compatible change"
	SEMVER_TOOLCHAIN=1.2.3 run "$GATE"
	[ "$status" -eq 0 ]
	[ "$(cat "$STUB_SELECTOR")" = "+1.2.3" ]
}

@test "no rustc at all is exit 2, never a fall back to a floating channel" {
	# Falling back to `stable` here is the defect this replaced: it is the one
	# answer that looks like a verdict and is not.
	rm "$BIN/rustc"
	graded 223
	PATH="$BIN:/usr/bin:/bin" run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no rustc on PATH"* ]]
}
