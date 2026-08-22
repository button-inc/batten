#!/usr/bin/env bash
#MISE description="Gate: no runnable doctest exists, because the workspace's test runner does not run them"
#
# THE COVERAGE HOLE A RUNNER SWAP OPENS, AND WHY IT IS A GATE RATHER THAN A NOTE
# (CLOUD-813). `[tasks."test:cargo"]` runs `cargo nextest run`, and nextest does
# not execute doctests — it says so itself and it is not a defect, it is the
# scheduler's scope. `cargo test` did run them. So the swap moves a class of test
# from "run on every PR" to "run nowhere", and the only thing that made that safe
# to do was a measurement: `cargo test --doc --workspace` reports
# `0 passed; 0 failed` on this workspace, so the class is EMPTY and nothing was
# lost.
#
# An empty class is not a stable property. The moment someone writes a doc
# example, it is dead code that reads like a tested example — the worst shape a
# test can take, because a reader trusts it precisely because it is executable.
# CLOUD-813's own words: a silent coverage change "is the one outcome that would
# make this a bad trade at any speed."
#
# So the emptiness is asserted rather than assumed. A doctest appearing is not
# forbidden — it is a decision this gate forces someone to make: run doctests as
# their own step, or mark the fence `text`/`ignore`. Either is fine; neither is
# silence.
#
# TEXT, NOT A COMPILE. The obvious predicate is `cargo test --doc` reporting
# zero, and it costs a full workspace build to answer a question the source
# already answers. This reads the fences.
#
# Output is a pointer, never the payload (non-negotiable 4): `path:line` and the
# fence's info string, never the example.
#
# Exit 0 no runnable doctest / 1 at least one / 2 could not look.
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "::error:: no-doctests: not a git repository, so there is nothing to scan" >&2
	exit 2
}

readonly ROOT="${1:-crates}"

if [[ ! -d "$ROOT" ]]; then
	echo "::error:: no-doctests: $ROOT is not a directory, so the scan has no subject. This is could-not-look, not clean." >&2
	exit 2
fi

# THE ANTI-VACUITY TERM. A scan that matched no file at all would report "no
# runnable doctest" over nothing, which is the reads-as-coverage defect
# CLOUD-418 names. Zero `.rs` files under the root is could-not-look.
files=$(git ls-files "$ROOT/**/*.rs" "$ROOT/*.rs" 2>/dev/null)
#MUTANT doctest-scan-may-be-vacuous|s@^if \[\[ -z "\${files//\[\[:space:\]\]/}" \]\]; then$@if false; then@|a root with no tracked .rs file is could-not-look
if [[ -z "${files//[[:space:]]/}" ]]; then
	echo "::error:: no-doctests: no tracked .rs file under $ROOT, so the scan has no subject. This is could-not-look, not clean." >&2
	exit 2
fi

# Fences INSIDE doc comments only (`///` and `//!`), toggled open/closed in
# order, because a closing fence carries no info string and would otherwise read
# as an unattributed — therefore runnable — opening one. rustdoc runs a fence
# unless its info string names one of the non-running attributes; `no_run` still
# compiles under `cargo test --doc` and is still not run by nextest, so it counts
# as non-running here and the gate stays about EXECUTION.
# `</dev/null` IS LOAD-BEARING, and the mutation harness is what found it. With
# the anti-vacuity arm above mutated away, `$files` is empty — and `awk` with a
# program but no file operands reads STDIN. Run from `mutant`'s
# `while read` loop that meant the gate silently ate the remaining declarations,
# so a second mutation row vanished and the task reported full coverage over one.
# In ordinary use it is a hang. A scanner must never be able to consume its
# caller's input.
found=$(
	# shellcheck disable=SC2086
	awk '
		FNR == 1 { open = 0 }
		{
			line = $0
			sub(/^[ \t]*/, "", line)
			if (line !~ /^\/\/[\/!]/) next
			sub(/^\/\/[\/!][ \t]?/, "", line)
			if (line !~ /^(```|~~~)/) next
			if (open) { open = 0; next }
			open = 1
			info = line
			sub(/^(```|~~~)[ \t]*/, "", info)
			if (info ~ /(^|[, ])(text|ignore|compile_fail|no_run)([, ]|$)/) next
			if (info == "") info = "(none)"
			printf "%s:%d\t%s\n", FILENAME, FNR, info
		}
	' $files </dev/null
)

#MUTANT runnable-fence-may-pass|s@^if \[\[ -n "\${found//\[\[:space:\]\]/}" \]\]; then$@if false; then@|an unattributed fence in a doc comment is refused
if [[ -n "${found//[[:space:]]/}" ]]; then
	count=$(printf '%s\n' "$found" | grep -c .)
	echo "::error:: no-doctests: $count runnable doctest fence(s). \`test:cargo\` runs \`cargo nextest run\`, which does not execute doctests, so this example is not run anywhere (CLOUD-813). Either give the fence \`text\`/\`ignore\`, or add a doctest step and say so here." >&2
	printf '%s\n' "$found" | while IFS=$'\t' read -r where info; do
		printf '  %s info=%s\n' "$where" "$info" >&2
	done
	exit 1
fi

echo "no-doctests: no runnable doctest fence under $ROOT, so nextest running none costs nothing"
