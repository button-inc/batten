#!/usr/bin/env bats
# subject: mise-tasks/board-sweep
# CLOUD-825. The seven board gates already compose; two of the three roots were
# never pulled and the third is fed `</dev/null`. This suite is about the CALLER
# and nothing else: each case asserts a gate was REACHED and its verdict carried,
# never that the gate's own predicate is right — that is each gate's own suite,
# and re-testing it here would be the second authority §1 refuses.
#
# Every fixture differs from a passing one in exactly one way, which is
# `tests/ci-local-parity.bats`'s shape and the reason a refusal can be attributed
# to the clause it came from.

setup() {
	load helpers
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/board-sweep"
	REPO="$BATS_TEST_TMPDIR/repo"
	# The developer's global git config must not reach a fixture repo (CLOUD-282).
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
	git update-ref refs/remotes/origin/main main
	# `released` resolves a range from a tag; a checkout with none is could not
	# look, which is its own case below rather than the ambient state.
	git tag v0.0.1 main

	# Every world-reading injected, so no case touches the network or `gh`.
	EV="$BATS_TEST_TMPDIR/merged.tsv"
	: >"$EV"
	export DRAIN_MERGED_PRS="$EV"
	export WIP_DRAIN_REFS="$BATS_TEST_TMPDIR/refs"
	: >"$WIP_DRAIN_REFS"
	export WIP_DRAIN_TODAY=2026-08-20
	export SPEC_REF_ROOT="$REPO"
	# An empty payload directory, so a case that means to pipe cannot silently
	# pick up this clone's own recovered payloads instead.
	export BOARD_PAYLOADS_DIR="$BATS_TEST_TMPDIR/payloads"
	mkdir -p "$BOARD_PAYLOADS_DIR"
	# The pull-request state `done-pr-check` refuses to license a Done without.
	PULLS="$BATS_TEST_TMPDIR/pulls.json"
	echo '[{"number":1,"state":"merged","draft":false}]' >"$PULLS"
	export SWEEP_PULLS="$PULLS"
}

# A row that satisfies every gate. Arguments override one field at a time, so a
# case's fixture differs from the clean one in exactly one way.
#   row <id> [status] [assignee] [attachments]
row() {
	local id=$1 status=${2:-In Progress}
	local assignee=${3:-\"t@t\"}
	local att=${4:-'[{"url":"https://github.com/o/r/pull/1"}]'}
	printf '{"id":"%s","status":"%s","updatedAt":"2026-08-20T00:00:00.000Z","gitBranchName":"x/%s","assignee":%s,"assigneeId":%s,"description":"a body","relations":{"blockedBy":[],"blocks":[],"relatedTo":[]},"attachments":%s}' \
		"$id" "$status" "$id" "$assignee" "$assignee" "$att"
}

set_of() { printf '[%s]' "$(printf '%s' "$*")"; }

sweep() { # sweep <json-array>
	run bash -c "printf '%s' '$1' | $GATE --payloads -"
}

# Adds a commit to main carrying $1 in its message.
land() {
	git checkout -q main
	git commit -q --allow-empty -m "$1"
	git update-ref refs/remotes/origin/main main
	git checkout -q work
}

# --- the clean board --------------------------------------------------------

@test "a set with no dissonance exits 0 and says every gate ran" {
	sweep "$(set_of "$(row CLOUD-1)")"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every gate ran"* ]]
}

@test "every gate is reached, and the report names each one" {
	sweep "$(set_of "$(row CLOUD-1)")"
	local g
	for g in released in-progress-drain done-pr-check spec-ref-check; do
		[[ "$output" == *"$g"* ]]
	done
}

# --- the two refusals CLOUD-825 names ---------------------------------------

@test "a landed-but-In-Progress row is named by in-progress-drain" {
	# CLOUD-469's shape: the column only grows because nothing asks. The drain
	# reaches `landed-check` behind it, and this asserts the caller carries that
	# verdict rather than that either gate computes it.
	land "feat: work

Closes CLOUD-1"
	printf 'CLOUD-1\t1\n' >"$EV"
	sweep "$(set_of "$(row CLOUD-1)")"
	[ "$status" -ne 0 ]
	[[ "$output" == *"in-progress-drain"* ]]
}

@test "a payload set reaches graph-check behind released" {
	# THE CASE THIS ROW'S OWN CORRECTION DEMANDS. `release-plz.yml` runs
	# `mise run released "$tag" </dev/null`, which takes the refs-only arm and
	# RETURNS before the `graph-check` invocation — so the composition runs on
	# every tag and decides nothing.
	#
	# Attribution is exact, and it has to be: the assertion is the rule NAME in
	# `released`'s own per-issue line — `REFUSED (in-review-no-pr)`. That string
	# exists nowhere else in the sweep. It is `graph-check`'s verdict, printed by
	# `released`, which can only have reached it by being handed the payload set
	# instead of `/dev/null`. `released` only consults the gate for issues the
	# TAG shipped, so the fixture lands a keyed commit inside the range first.
	land "feat: work

Closes CLOUD-1"
	git tag v0.0.2 main
	sweep "$(set_of "$(row CLOUD-1 "In Review" '"t@t"' '[]')")"
	[ "$status" -ne 0 ]
	[[ "$output" == *"REFUSED (in-review-no-pr)"* ]]
}

# --- could not look ---------------------------------------------------------

@test "an empty payload set is COULD NOT LOOK, not a clean board" {
	# The anti-vacuity case, and the one a composer gets wrong: every gate below
	# finds nothing to refuse over an empty set, so the sweep would report the
	# board coherent having looked at no row at all.
	run bash -c "printf '' | $GATE --payloads -"
	[ "$status" -eq 2 ]
	[[ "$output" != *"every gate ran"* ]]
	# THE VERDICT MUST BE THIS TASK'S OWN. Asserting only the exit code cannot
	# discriminate: without the guard, `released` chokes on the empty set and
	# exits 2 by itself, so the sweep still reports 2 — for a reason that has
	# nothing to do with having noticed. A composer that inherits its
	# anti-vacuity from whichever gate happens to fail first has none.
	[[ "$output" == *"the payload set is empty"* ]]
}

@test "a gate exiting 2 is not laundered into the refusal lane" {
	# `done-pr-check` exits 2 when a row names a PR whose state is not piped —
	# a Done granted over an unread PR is the defect it exists to refuse, so an
	# absent state must not become the cheap path to the same outcome.
	echo '[]' >"$PULLS"
	sweep "$(set_of "$(row CLOUD-1)")"
	[ "$status" -eq 2 ]
	[[ "$output" == *"done-pr-check COULD NOT LOOK"* ]]
	[[ "$output" != *"done-pr-check REFUSED"* ]]
}

@test "could not look outranks a refusal, so a half-run sweep is never exit 1" {
	# Both at once: `released` cannot resolve a range without a tag, and the
	# drain has a landed row to name. The sweep has not judged the board, and
	# saying "dissonance found" would imply it had.
	git tag -d v0.0.1
	land "feat: work

Closes CLOUD-1"
	printf 'CLOUD-1\t1\n' >"$EV"
	sweep "$(set_of "$(row CLOUD-1)")"
	[ "$status" -eq 2 ]
}

# --- rule 4 -----------------------------------------------------------------

@test "the report carries no issue body" {
	# Pointer-only: issue keys, gate names and counts. A sweep that quoted a body
	# would be the payload-reading this repository forbids everywhere else, and
	# the bodies are the largest thing it holds.
	land "feat: work

Closes CLOUD-1"
	git tag v0.0.2 main
	sweep "$(set_of "$(row CLOUD-1 "In Review" '"t@t"' '[]')")"
	[[ "$output" != *"a body"* ]]
}
