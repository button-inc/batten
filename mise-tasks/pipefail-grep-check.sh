#!/usr/bin/env bash
#MISE description="Gate: under set -o pipefail, no shell task pipes a producer into an early-exiting grep -q"
#
# `producer | grep -q PATTERN` under `set -o pipefail` can return FAILURE on a
# match. grep exits the moment it finds the first hit; if the producer is still
# writing it dies of SIGPIPE, and pipefail promotes that signal (141) to the
# pipeline's status. So the successful case is the one that reports failure.
#
# It is a RACE, which is exactly what lets it survive review and a green suite:
# whether the producer is still writing when grep exits depends on output size
# and scheduling. Measured here on a two-commit range — 2 failures in 300 runs,
# and one of those two was a real denial of a correctly-referenced PR. A large
# producer loses the race nearly always; a small one loses it rarely, passes
# every test written for it, and denies someone months later.
#
# Two instances landed in this repo before the class was named:
#
#   landed-check  read `git log … | grep -q "$id"` and reported a CLEAN BOARD
#                 over three issues whose refs were on main.
#   issue-guard   asked the same way whether any commit on the branch names an
#                 issue, and DENIED `gh pr ready` on a branch where every commit
#                 carried `Refs: CLOUD-186` — with a reason stating the opposite
#                 of what it had just found. The gate blocked its own PR.
#
# Both fail in the same direction: toward the verdict nobody checks. A gate that
# reports clean when it found something, and a guard that refuses work that
# satisfied it, are the silent false green this repo keeps re-meeting in a new
# disguise.
#
# The fix needs no new tool and is always the same shape: read the producer into
# a variable and match from a here-string — `x=$(producer); grep -q P <<<"$x"`.
# A here-string has no upstream process, so there is no status to promote.
#
# Scope, deliberately: only files that actually enable pipefail, and only the
# early-exiting forms (`-q`, `-m N`, and `-l`, which stops at the first matching
# file). `| grep` without them consumes its whole input, so the producer never
# takes SIGPIPE and the pipeline status is honest.
set -euo pipefail

fail=0
report() {
	[ "$fail" = 0 ] && echo "::error:: a producer is piped into an early-exiting grep under pipefail, so a MATCH reports failure (see mem:toolchain-and-hooks):" >&2
	printf '  %s\n' "$1" >&2
	fail=1
}

while IFS= read -r -d '' file; do
	grep -qE '^[[:space:]]*set[[:space:]]+-[a-z]*o?[a-z]*[[:space:]]*.*pipefail' "$file" || continue

	# -H because grep omits the filename for a single path, which would silently
	# turn the pointer into "lineno:text" and misreport the location.
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		lineno=${hit%%:*}
		text=${hit#*:}
		# A comment describing the hazard is not the hazard.
		[[ "$(sed -E 's/^[[:space:]]*//' <<<"$text")" == \#* ]] && continue
		# Judge the flags of the piped-into grep itself. `-qxF` and `-oq` are the
		# same hazard as `-q`, so the test is "a short-flag cluster containing q
		# or l", not an exact spelling — the enumeration is what would rot.
		piped=${text##*| grep}
		[ "$piped" = "$text" ] && piped=${text##*|grep}
		early=0
		for tok in $piped; do
			case "$tok" in
			--) break ;;
			--quiet | --files-with-matches | --max-count*) early=1 ;;
			-m*) early=1 ;;
			--*) ;;
			-*)
				# A short-flag cluster: q or l anywhere in it exits early.
				case "${tok#-}" in
				*[ql]*) early=1 ;;
				esac
				;;
			esac
		done
		[ "$early" = 1 ] || continue
		report "$file:$lineno: pipes into an early-exiting grep — read into a variable and match with <<<"
		# `||` IS NOT A PIPE. The scan was `\|[[:space:]]*grep`, which matches the
		# SECOND bar of `a || grep -q ...` and reports a here-string form — the
		# very remedy this gate recommends — as the defect it exists to refuse.
		# Measured on `mise-tasks/ready-lint.sh` (CLOUD-852), whose line reads
		# `[[ ... ]] || grep -qE '...' <<<"$var"` and pipes nothing.
	done < <(grep -nE '(^|[^|])\|[[:space:]]*grep([[:space:]]|$)' "$file" || true)
done < <(git ls-files -z 'mise-tasks/*' '*.sh' 2>/dev/null || true)

[ "$fail" = 0 ] && echo "pipefail-grep-check: no producer is piped into an early-exiting grep"
exit "$fail"
