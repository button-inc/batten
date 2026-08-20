#!/usr/bin/env bats
# CLOUD-469. `landed-check` computes the right predicate and nothing calls it, so
# the In Progress column has no drain and only grows — 39 rows for one assignee on
# 2026-08-12, still 32 on 2026-08-20 with 20 of them behind git.
#
# This gate reports two verdicts. `landed-unswept` is DELEGATED to `landed-check`
# and never recomputed, so these cases assert the delegation carries rather than
# re-testing that task's own predicate. `claimed-abandoned` is a five-way
# conjunction, and most of this file exists to prove it is one: a claim that
# fails any single conjunct is live work, and naming live work as dead is worse
# than the stale column it fixes.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/in-progress-drain"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	# The developer's global git config must not reach a fixture repo (CLOUD-282);
	# `init.defaultBranch` and `commit.gpgsign` are the two that have leaked here.
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
	git update-ref refs/remotes/origin/main main

	# Both world-readings injected, so no case touches the network or `gh`.
	REFS="$BATS_TEST_TMPDIR/refs-$BATS_TEST_NUMBER"
	: >"$REFS"
	export WIP_DRAIN_REFS="$REFS"
	export WIP_DRAIN_TODAY=2026-08-20
	# The merged-PR evidence is the third injected world-reading (CLOUD-804).
	# `landed-check` refuses without it rather than reporting a clean column, so
	# a case that forgets it fails loudly instead of passing vacuously.
	EV="$BATS_TEST_TMPDIR/merged-$BATS_TEST_NUMBER.tsv"
	: >"$EV"
	export DRAIN_MERGED_PRS="$EV"
}

# Records that a MERGED pull request $2 closed issue $1.
merged_pr() {
	printf '%s\t%s\n' "$1" "$2" >>"$EV"
}

# Adds a commit to main carrying $1 in its message.
land() {
	git checkout -q main
	git commit -q --allow-empty -m "$1"
	git update-ref refs/remotes/origin/main main
	git checkout -q work
}

# row <id> <updatedAt> <gitBranchName> <attachment-url>
# An empty attachment url means no attachments at all.
row() {
	local att="[]"
	[ -n "${4:-}" ] && att="[{\"url\":\"$4\"}]"
	printf '{"id":"%s","status":"In Progress","updatedAt":"%s","gitBranchName":"%s","attachments":%s}' \
		"$1" "$2" "$3" "$att"
}

drain() {
	run bash -c "printf '%s' '$1' | $GATE"
}

# --- the delegated half -------------------------------------------------------

@test "an In Progress issue whose commits are on main is landed-unswept" {
	land "feat: work

Closes CLOUD-179"
	drain "[$(row CLOUD-179 2026-08-20T10:00:00.000Z feat/x '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"landed-unswept"* ]]
	[[ "$output" == *"CLOUD-179"* ]]
}

@test "a landed row is not ALSO reported as abandoned — the verdicts are exclusive" {
	# Idle, no branch, no PR: it satisfies every abandoned conjunct except the
	# first. Being on `main` is the whole difference, and this is the case the
	# `abandoned-ignores-landed` mutation reddens.
	land "feat: work

Closes CLOUD-179"
	drain "[$(row CLOUD-179 2026-01-01T10:00:00.000Z feat/x '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"landed-unswept"* ]]
	[[ "$output" != *"::error:: claimed-abandoned"* ]]
	[[ "$output" == *"1 landed-unswept, 0 claimed-abandoned"* ]]
}

@test "the landed report says it is candidates, and names what decides a move" {
	# CLOUD-804: `landed-check` matches a bare MENTION, so this list is not an
	# adjudication and must not read as one. Measured on the live board
	# 2026-08-20: of 19 named, 2 had their live work in an open PR. Pinned as a
	# case because the harm is silent — a reader acting on the list in bulk has
	# no way to tell, which is how CLOUD-480 sat wrong for 4.5 hours.
	land "feat: work

Closes CLOUD-179"
	drain "[$(row CLOUD-179 2026-08-20T10:00:00.000Z feat/x '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"board-move-guard"* ]]
	# Landed is a fact about the COLUMN, never about completeness — that is
	# `released`'s question and this must not appear to answer it.
	[[ "$output" == *"released"* ]]
}

# The delegation carries CLOUD-804's precision through rather than re-deciding
# it here. The fixture is verbatim from main's log on 2026-08-20, where it was
# reported landed while the work sat in open PR #579.
@test "a citation on main is not landed-unswept, through the delegation" {
	land "feat(ci): verify the declared MSRV against the compiler it names

on the newer compiler while the published claim quietly goes false. That is
CLOUD-271's shape."
	drain "[$(row CLOUD-271 2026-08-20T10:00:00.000Z feat/x 'https://github.com/o/r/pull/579')]"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 landed-unswept"* ]]
}

@test "a merged PR in the evidence lands a row with no closing key on main" {
	land "fix(doctor): serialize the two repairs doctor's own graph races"
	merged_pr CLOUD-201 339
	drain "[$(row CLOUD-201 2026-08-20T10:00:00.000Z feat/x '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-201"* ]]
}

@test "a clean board is exit 0 and says so" {
	drain "[]"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 In Progress — 0 landed-unswept, 0 claimed-abandoned"* ]]
}

@test "a row in another column is judged by neither verdict" {
	land "feat: work

Closes CLOUD-179"
	drain '[{"id":"CLOUD-179","status":"In Review"}]'
	[ "$status" -eq 0 ]
}

# --- the abandoned conjunction, one failing conjunct at a time ----------------

@test "all five conjuncts satisfied is claimed-abandoned" {
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"claimed-abandoned"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
	[[ "$output" == *"0 landed-unswept, 1 claimed-abandoned"* ]]
}

@test "a claim carrying a PR attachment is not abandoned" {
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone https://github.com/o/r/pull/12)]"
	[ "$status" -eq 0 ]
	[[ "$output" != *"::error:: claimed-abandoned"* ]]
}

@test "a non-PR attachment does not rescue a claim — only a pull request does" {
	# The conjunct is "no PR", not "no attachments". A design doc linked on the
	# row is not evidence that work left the machine.
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone https://linear.app/x/document/y)]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"claimed-abandoned"* ]]
}

@test "a claim with a live remote branch is not abandoned" {
	echo "feat/live" >"$REFS"
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/live '')]"
	[ "$status" -eq 0 ]
	[[ "$output" != *"::error:: claimed-abandoned"* ]]
}

@test "a claim touched today is not abandoned" {
	drain "[$(row CLOUD-124 2026-08-20T09:00:00.000Z feat/gone '')]"
	[ "$status" -eq 0 ]
	[[ "$output" != *"::error:: claimed-abandoned"* ]]
}

@test "the idle bound is exclusive at exactly the threshold" {
	# 2 days idle with WIP_MAX_IDLE_DAYS=2 is NOT over the bound. Stated as a case
	# because an off-by-one here silently converts two days of live work into a
	# dead claim, and nothing downstream would question the label.
	drain "[$(row CLOUD-124 2026-08-18T09:00:00.000Z feat/gone '')]"
	[ "$status" -eq 0 ]
	drain "[$(row CLOUD-124 2026-08-17T09:00:00.000Z feat/gone '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"claimed-abandoned"* ]]
}

@test "the idle bound is configurable and the report names the value it used" {
	WIP_MAX_IDLE_DAYS=30 run bash -c "printf '%s' '[$(row CLOUD-124 2026-08-01T09:00:00.000Z feat/gone '')]' | $GATE"
	[ "$status" -eq 0 ]
	WIP_MAX_IDLE_DAYS=5 run bash -c "printf '%s' '[$(row CLOUD-124 2026-08-01T09:00:00.000Z feat/gone '')]' | $GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"idle > 5d"* ]]
}

# --- could-not-look, never a silent pass --------------------------------------

@test "an In Progress row with no attachments key is exit 2 and named" {
	drain '[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","gitBranchName":"x"}]'
	[ "$status" -eq 2 ]
	[[ "$output" == *"attachments"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
}

@test "an In Progress row with no gitBranchName key is exit 2 and named" {
	drain '[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","attachments":[]}]'
	[ "$status" -eq 2 ]
	[[ "$output" == *"gitBranchName"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
}

@test "an In Progress row with no updatedAt key is exit 2 and named" {
	drain '[{"id":"CLOUD-124","status":"In Progress","gitBranchName":"x","attachments":[]}]'
	[ "$status" -eq 2 ]
	[[ "$output" == *"updatedAt"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
}

@test "a FRESH row is not demanded of attachments — the idle bound already resolved it" {
	# This is the cost argument as a test. `list_issues` projects id, status,
	# gitBranchName and updatedAt but CANNOT project attachments, so `get_issue`
	# — which takes no field selection and drags the whole body — is the only
	# source of the last key. Ordering the conjuncts by what is projectable means
	# that fetch is paid only for rows that are landed-free AND past the bound.
	# Measured on the live board 2026-08-20: 7 full fetches instead of 32.
	drain '[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-08-20T09:00:00.000Z"}]'
	[ "$status" -eq 0 ]
	[[ "$output" != *"::error::"* ]]
}

@test "a stale row IS demanded of attachments — the narrowing is not a hole" {
	drain '[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T09:00:00.000Z"}]'
	[ "$status" -eq 2 ]
	[[ "$output" == *"attachments"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
}

@test "a LANDED row is not demanded of those keys — it is already answered" {
	# `landed-check` decides landedness from id and status alone. Demanding three
	# more keys to re-answer a row it already resolved would refuse a sweep that
	# has no question about it, and would break the cheap staging the issue
	# specifies: a projected `list_issues` over the column, then `get_issue` only
	# for the rows that failed the ref test.
	land "feat: work

Closes CLOUD-179"
	drain '[{"id":"CLOUD-179","status":"In Progress"}]'
	[ "$status" -eq 1 ]
	[[ "$output" == *"landed-unswept"* ]]
	[[ "$output" != *"::error:: in-progress-drain"* ]]
}

@test "an UNRESOLVED row missing a key is still exit 2, alongside a landed one" {
	# The narrowing must not become a hole: a row the abandoned verdict has to
	# judge still cannot be judged without its keys, even when the same payload
	# carries a landed row that needs none.
	land "feat: work

Closes CLOUD-179"
	drain '[{"id":"CLOUD-179","status":"In Progress"},{"id":"CLOUD-124","status":"In Progress"}]'
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-124"* ]]
	[[ "$output" != *"CLOUD-179"* ]]
}

@test "a row in another column is not demanded of those keys" {
	# The keys are needed to judge a claim. A Done row is not being judged, so
	# demanding them would refuse a sweep it has no question about — the
	# over-refusal twin of the silent scan.
	drain '[{"id":"CLOUD-124","status":"Done"}]'
	[ "$status" -eq 0 ]
}

@test "presence is what is checked, not truthiness" {
	# An empty attachments array and an empty gitBranchName are DATA: they say
	# "no PR" and "no branch", which is exactly what the conjunction asks. A guard
	# testing truthiness would refuse the very payload it is meant to judge.
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z '' '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"claimed-abandoned"* ]]
}

@test "an unreadable updatedAt is reported, never silently treated as fresh" {
	drain '[{"id":"CLOUD-124","status":"In Progress","updatedAt":"not-a-date","gitBranchName":"x","attachments":[]}]'
	[ "$status" -eq 1 ]
	[[ "$output" == *"unreadable-updatedat"* ]]
	[[ "$output" == *"CLOUD-124"* ]]
}

@test "empty stdin is exit 2, not a clean board" {
	run bash -c ": | $GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "a payload missing id or status is exit 2" {
	drain '[{"status":"In Progress"}]'
	[ "$status" -eq 2 ]
}

@test "an unreadable WIP_DRAIN_REFS is exit 2, not an empty branch list" {
	# An unreadable refs file and a remote with no branches are the same silent
	# false green: every claim would look branchless and therefore abandoned.
	WIP_DRAIN_REFS="$BATS_TEST_TMPDIR/nope" run bash -c "printf '%s' '[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone '')]' | $GATE"
	[ "$status" -eq 2 ]
}

@test "an unreadable WIP_DRAIN_TODAY is exit 2" {
	WIP_DRAIN_TODAY=nonsense run bash -c "printf '%s' '[$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone '')]' | $GATE"
	[ "$status" -eq 2 ]
}

# --- the output contract ------------------------------------------------------

@test "the report carries keys and counts, never a body" {
	# Non-negotiable 4: output is a pointer, never the payload. Asserted rather
	# than trusted, because the payload this reads is the richest text surface
	# the board has.
	local secret="SENSITIVE-BODY-TEXT-DO-NOT-EMIT"
	drain "[{\"id\":\"CLOUD-124\",\"status\":\"In Progress\",\"updatedAt\":\"2026-01-01T00:00:00.000Z\",\"gitBranchName\":\"feat/gone\",\"attachments\":[],\"description\":\"$secret\"}]"
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}

@test "both verdicts report together, each under its own label" {
	land "feat: work

Closes CLOUD-179"
	drain "[$(row CLOUD-179 2026-08-20T10:00:00.000Z feat/x ''),$(row CLOUD-124 2026-01-01T10:00:00.000Z feat/gone '')]"
	[ "$status" -eq 1 ]
	[[ "$output" == *"landed-unswept"* ]]
	[[ "$output" == *"claimed-abandoned"* ]]
	[[ "$output" == *"2 In Progress — 1 landed-unswept, 1 claimed-abandoned"* ]]
}

@test "the id list is byte-stable regardless of input order" {
	drain "[$(row CLOUD-9 2026-01-01T10:00:00.000Z a ''),$(row CLOUD-124 2026-01-01T10:00:00.000Z b '')]"
	local first="$output"
	drain "[$(row CLOUD-124 2026-01-01T10:00:00.000Z b ''),$(row CLOUD-9 2026-01-01T10:00:00.000Z a '')]"
	[ "$output" = "$first" ]
}
