#!/usr/bin/env bash
#MISE description="Append a measurement to the trunk's invocation-cost series in git notes (reads `perf` records on stdin; refuses to run off main)"
#
# CLOUD-172. CLOUD-207 published one number, and a number measured once decays
# in silence: nobody notices 3ms becoming 40ms, they notice months later that
# the hook got uninstalled. This is the series that makes the decay visible, and
# a regression attributable to a SHA rather than to a quarter.
#
# GIT NOTES, NOT AN EXTERNAL SERVICE. `refs/notes/perf`, keyed to the commit
# measured. Three properties follow from that choice and none of them are
# available from a dashboard: the history travels with the clone, a reader can
# ask `git log --notes=perf` and get the series interleaved with the commits
# that caused it, and nothing has to be re-run to attribute a change. It also
# costs no credential and no vendor.
#
# MAIN ONLY, and this is a refusal rather than a convention. A branch's numbers
# are not the trunk's: a branch may be mid-rebase, carrying unlanded work, or
# built from a different base entirely, and a series mixing the two cannot be
# read at all — the reader has no way to tell a step change from a branch
# switch. So a non-main HEAD is exit 1, loudly, and nothing is written.
#
# THE LABEL IS LOAD-BEARING. CLOUD-172 asked for instruction counts as the
# primary metric, with wall clock as the fallback "where valgrind is
# unavailable". Measured here: `mise registry valgrind` reports "tool not found
# in registry", so valgrind cannot be pinned in `mise.toml` at all, and
# `batten.toml`'s `no-source-built-tool` rule refuses to compile it. Wall clock
# is therefore the metric everywhere, not situationally — which makes saying so
# in the record mandatory, since a later reader comparing a wall-clock series
# against an instruction-count one would read the instrument change as a
# regression. `metric=` is that guard.
#
# THE RECORDING TRIGGER, decided as the Ready block requires. NOT a
# push-to-`main` workflow: AGENTS.md's workflow contract forbids one, and the
# reason holds here rather than merely applying — `main` only advances by
# fast-forward to a SHA CI already judged, so a push trigger buys a runner per
# merge for a measurement that a schedule can take just as well. The trigger is
# the daily schedule in `.github/workflows/perf.yml`, which already samples
# `main`. What that costs is resolution: the series is per-sample, not
# per-commit. That trade is affordable precisely because it is not the only
# mechanism — `perf-compare` catches a regression on the PULL REQUEST that
# caused it, at the commit that caused it, which is where attribution actually
# matters. The series carries the trend. (Recorded in .claude/rules/toolchain.md
# too; AGENTS.md is at its budgeted line ceiling and already carries the rule
# this decision honours.)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The ref the series lives on. Its own ref, not `refs/notes/commits`: the
# default notes ref is what `git notes` writes with no argument and what a
# contributor is most likely to have local edits on, and a series is not a
# comment.
readonly NOTES_REF="${BENCH_NOTES_REF:-refs/notes/perf}"

# The branch a measurement is allowed to describe. An argument so the bats suite
# can drive a fixture repository whose trunk is named something else; the real
# value is this repo's trunk.
readonly TRUNK="${BENCH_TRUNK:-main}"

# What produced the numbers. Emitted into the record so the series can never be
# read as an instruction count — see the header.
readonly METRIC="${BENCH_METRIC:-wall-clock}"

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "$TRUNK" ]]; then
	echo "::error:: perf-record: HEAD is on '$branch', not '$TRUNK' — a branch's numbers are not the trunk's, and a series mixing them cannot be read. Nothing written." >&2
	exit 1
fi

commit="$(git rev-parse HEAD)"

# Exit 2 for "could not look", matching `perf-assert` and the `lock-complete`
# doctrine: a caller that redirected nothing here needs to hear that, not a
# silent empty note that later reads as a measurement of zero.
records="$(cat)"
if [[ -z "${records//[[:space:]]/}" ]]; then
	echo "::error:: perf-record: stdin is empty — redirect \`mise run perf\` to a file and read it back. Nothing written." >&2
	exit 2
fi

# Only records. A stray line would enter the series as a datum nothing can
# parse, and the series is read by machine (`perf-compare`) as well as by eye.
# Literal awk patterns, never a `-v` regex — `mise run awk-regex-check` refuses
# the latter for having implementation-defined escape handling.
if awk '/^path=/ { next } /[^[:space:]]/ { bad = 1 } END { exit !bad }' <<<"$records"; then
	echo "::error:: perf-record: stdin carries lines that are not \`perf\` records, so the series would take a datum nothing can parse. Nothing written." >&2
	exit 2
fi

# One note per commit, and appending rather than replacing: a commit sampled
# twice (a re-dispatched schedule, a manual run) keeps both readings instead of
# the second silently overwriting the first. Two readings of one commit is
# itself the noise measurement a threshold wants.
note="$(printf 'metric=%s runner=%s\n%s' "$METRIC" "${BENCH_RUNNER:-$(uname -m)-$(nproc)core}" "$records")"

if ! git notes --ref="$NOTES_REF" append -m "$note" "$commit"; then
	echo "::error:: perf-record: could not append the note to $NOTES_REF for $commit." >&2
	exit 1
fi

# A pointer, never the payload (non-negotiable rule 4): the ref and the commit,
# so a reader knows where to look. The numbers are in the note.
echo "perf-record: appended a $METRIC measurement to $NOTES_REF for ${commit:0:8}"
