#!/usr/bin/env bash
#MISE description="Which bats suites this diff can move, by declared subject — or all of them (CLOUD-886)"
#
# `hk.pkl` selects the `test:bats` step with `glob = List("mise-tasks/**",
# "tests/*.bats")`, so any byte changed under `mise-tasks/` runs ALL of them:
# 1,188s serial, ~290s at `--jobs 4`, and ~81% of the `ci` job. Measured,
# correcting ONE SENTENCE in `mise-tasks/land`'s lap-cap message bought a full
# matrix. That is not an edge case — CLOUD-843's waves touch `mise-tasks/` on
# every lap.
#
# The two inputs selection needs both exist, and neither did a day before this:
# every suite declares its subject (CLOUD-807's `# subject:`, 151 of 151), and
# every suite's cost is recorded (`bench/suites/RESULTS.md`). So "which suites can
# this diff move, and what do they cost" is answerable from committed text.
#
# ─── THE ASYMMETRY DECIDES THE WHOLE DESIGN ─────────────────────────────────
#
# A selection that is too WIDE costs money and is obvious in the bill. A selection
# that is too NARROW does not fail: the suites simply do not run, the count
# matches whatever was selected, and a regression lands green. There is no
# symptom. So this is a DENY-LIST, never an allow-list: selection applies only
# when every changed path is provably inert with respect to every other suite, and
# anything else runs everything.
#
# That is not caution for its own sake. Several subjects are inputs to nearly
# every suite — `mise.toml` defines the tasks the suites invoke, `hk.pkl` defines
# the gate, `batten.toml` is the policy authority, `tests/helpers` is sourced
# widely. Subject-intersection alone would select 7 suites for a `mise.toml` edit
# and skip `tests/land.bats`, which is WORSE than running everything.
#
# Output is the selected suite paths on stdout, one per line, sorted. The reason a
# wide run was chosen goes to stderr as a pointer — a count and a path, never a
# diff and never a case name (non-negotiable rule 4).
#
# Exit 0 a selection was computed (wide or narrow) / 2 could not look.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

# TRACKED AND UNTRACKED, because the changed-set path already selects an
# untracked suite and a wide run that could not see one would skip it silently
# (CLOUD-480, found on review of #660). `--others --exclude-standard` is the
# union without the ignored files, so scratch under `tests/` stays out by the
# same rule that keeps it out of the changed set.
# PRESENT IN THE WORKING TREE, and that is the same rule `suites_for` applies to
# a deleted path: every path this emits is one the consumer hands to bats, and a
# file bats cannot open is not a suite to run. `--cached` lists INDEX entries, so
# a suite deleted from the working tree is still listed until the removal is
# staged — which is exactly the state a retirement passes through.
all_suites() {
	local path
	git ls-files --cached --others --exclude-standard -- 'tests/*.bats' |
		LC_ALL=C sort -u |
		while IFS= read -r path; do
			if [[ -f "$path" ]]; then
				printf '%s\n' "$path"
			fi
		done
}

# EVERYTHING, and say why on stderr. Every path out of this function is a
# deliberate widening, so each one names its reason rather than falling through
# silently — a wide run with no stated cause is indistinguishable from a selector
# that is not working.
wide() { # wide <reason>
	echo "suite-select: running every suite — $1" >&2
	all_suites
	exit 0
}

# The paths this working tree changes against the trunk, committed or not.
#
# Untracked files are included because opening a new suite is the first thing
# this must not miss, and a `tests/<name>.bats` that exists only in the working
# tree still needs to run.
base="${BASE_SHA:-origin/main}"
git rev-parse --verify --quiet "$base" >/dev/null ||
	wide "no $base to compare against, so the changed set is unknowable"

changed=$(
	{
		git diff --name-only "$base...HEAD" 2>/dev/null
		git diff --name-only HEAD 2>/dev/null
		git ls-files --others --exclude-standard 2>/dev/null
	} | LC_ALL=C sort -u
)
# An empty changed set is not "nothing to run": it is a question this could not
# answer, because a caller running the task by hand on a clean tree still wants
# the suite. Could-not-look widens.
[[ -n "${changed//[[:space:]]/}" ]] ||
	wide "no changed paths could be computed"

# ─── the deny list ──────────────────────────────────────────────────────────
#
# A shared input is one that can move a suite whose subject does not name it.
# Enumerated rather than inferred, and the enumeration is the conservative
# direction: a path NOT listed here still has to match the narrow shape below to
# avoid a wide run, so a shared input somebody forgets to add is caught by the
# shape test instead of slipping through.
shared_input() { # shared_input <path>
	case "$1" in
	mise.toml | mise.lock | hk.pkl | batten.toml | .claude/settings.json) return 0 ;;
	tests/helpers*) return 0 ;;
	esac
	return 1
}

# The suites a changed path can move.
#
# `mise-tasks/<name>` resolves through the declared `# subject:` headers; a
# `tests/<name>.bats` selects itself. Nothing is inferred from the filename:
# CLOUD-807 measured 19 of 142 suites with no same-named program and every one
# legitimate, so a name heuristic would both skip real work and select the wrong
# thing.
suites_for() { # suites_for <path>
	local path="$1"
	case "$path" in
	tests/*.bats)
		# A DELETED SUITE HAS NOTHING TO RUN (CLOUD-480, found on review of
		# #660). `git diff --name-only` reports deleted paths, so a retirement
		# that removes `tests/foo.bats` selected it and handed bats a path that
		# does not exist — reachable in this very campaign, which retires suites.
		# Dropping it narrows no real coverage.
		[[ -f "$path" ]] || return 1
		printf '%s\n' "$path"
		return 0
		;;
	esac
	# The header is `# subject:` followed by whitespace-separated paths, so the
	# match is on a whole field rather than a substring: `mise-tasks/land` must
	# not select a suite whose subject is `mise-tasks/land-lock`.
	local suite subjects field found=1
	while IFS= read -r suite; do
		subjects=$(sed -n 's/^# subject:[[:space:]]*//p' "$suite" 2>/dev/null)
		for field in $subjects; do
			if [[ "$field" == "$path" ]]; then
				printf '%s\n' "$suite"
				found=0
				break
			fi
		done
	done < <(all_suites)
	return "$found"
}

selected=""
while IFS= read -r path; do
	[[ -n "$path" ]] || continue
	if shared_input "$path"; then
		wide "$path is an input to suites whose subject does not name it"
	fi
	case "$path" in
	mise-tasks/* | tests/*.bats) ;;
	*)
		wide "$path is outside the set selection can reason about"
		;;
	esac
	# A path under `mise-tasks/` that no suite declares as its subject is a
	# program nothing covers, or a header that has rotted. Either way this cannot
	# say which suites it moves, and could-not-look widens.
	hits=$(suites_for "$path") ||
		wide "no suite declares $path as its subject"
	[[ -n "${hits//[[:space:]]/}" ]] ||
		wide "no suite declares $path as its subject"
	selected+="$hits"$'\n'
done <<<"$changed"

printf '%s' "$selected" | LC_ALL=C sort -u | sed '/^$/d'
