#!/usr/bin/env bats
# The predicate behind In Review -> Done (CLOUD-174), and its refusal (CLOUD-257).
#
# `released` resolves refs from a tag's commit range, so it answers "did a tag
# ship a commit naming this issue" — not "is this issue finished". Used as the
# sole authority on a TERMINAL transition that closes work that is still open;
# measured, it reported CLOUD-108 and CLOUD-202 as movable when neither was done.
# Remaining scope is not computable from git, so the mechanism is the refusal: an
# issue carrying the hold marker is reported HELD and the run exits 1.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/released"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || return 1
	git init -q -b main .
	git config user.email t@example.com
	git config user.name t
	git config commit.gpgsign false
	commit "feat: the first thing" "Refs: CLOUD-1"
	git tag v0.0.1
	commit "feat: the second thing" "Refs: CLOUD-2"
	commit "fix: the third thing" "Refs: CLOUD-3"
	git tag v0.0.2
}

commit() {
	git commit -q --allow-empty -m "$1" -m "${2:-}"
}

# A payload set, one {id,status,description} per issue.
payload() {
	local out="[" first=1 spec id status body
	for spec in "$@"; do
		id="${spec%%:*}"
		status="${spec#*:}"
		body="${status#*:}"
		status="${status%%:*}"
		[ "$body" != "$spec" ] || body=""
		[ "$first" = 1 ] || out="$out,"
		first=0
		# CLOUD-309: `attachments` is now part of the question, so every fixture
		# carries one. An issue with a linked PR is the ordinary case; the
		# fixtures that model a bare board write it explicitly as `[]`.
		out="$out{\"id\":\"$id\",\"status\":\"$status\",\"description\":\"$body\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}]}"
	done
	printf '%s]' "$out]" | sed 's/]]$/]/'
}

@test "with no stdin it reports what the tag shipped" {
	run bash -c "'$TASK' v0.0.2 </dev/null"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2"* ]]
	[[ "$output" == *"CLOUD-3"* ]]
	# Scoped to the range, so the previous tag's issue is not re-reported.
	[[ "$output" != *"CLOUD-1"* ]]
}

@test "an In Review issue the tag shipped is movable" {
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" == *"1 to move"* ]]
}

@test "an issue in any other state is left alone, never touched" {
	run bash -c "printf '%s' '$(payload CLOUD-2:Done)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" != *"-> Done"* ]]
}

@test "THE REFUSAL: an issue holding itself open is HELD, not movable" {
	# CLOUD-108's shape. Its body says DO NOT CLOSE UNTIL THE MATRIX HAS RUN
	# GREEN and names closing on \"the commits released\" as the exact trap; the
	# sweep reported it movable anyway, and it was moved and reverted.
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:blocked,\ DO-NOT-CLOSE\ until\ the\ matrix\ is\ green)' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  HELD"* ]]
	[[ "$output" == *"0 to move"* ]]
	[[ "$output" == *"1 HELD"* ]]
}

@test "the refusal says why shipping is not enough, not merely that it refused" {
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:DO-NOT-CLOSE)' | '$TASK' v0.0.2"
	[[ "$output" == *"necessary for Done, not sufficient"* ]]
}

@test "a held issue does not suppress the movable ones beside it" {
	# The report must stay complete: a caller acts on what it can and resolves
	# the hold separately. Swallowing the movable list would make the refusal
	# cost more than it saves, and it would get bypassed.
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review:DO-NOT-CLOSE CLOUD-3:In\ Review)' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  HELD"* ]]
	[[ "$output" == *"CLOUD-3  In Review -> Done"* ]]
}

@test "the marker only holds an In Review issue — a Done one is already past it" {
	run bash -c "printf '%s' '$(payload CLOUD-2:Done:DO-NOT-CLOSE)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" != *"HELD"* ]]
}

@test "an issue with no marker and no description still moves" {
	# The marker is opt-in: a body that does not carry it keeps the old answer,
	# so this cannot quietly freeze the whole board.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"In Review -> Done"* ]]
}

@test "THE SECOND WAY IN: no ref in the range, but a commit the tag contains" {
	# CLOUD-260. The grep rests on issue-guard making the ref mandatory, which is
	# not true retroactively: four issues had landed work behind merged PRs and
	# zero mentions in main's entire history, so no tag could ever name them and
	# they sat In Review permanently. A commit the caller supplies is the second
	# evidence, and containment in this tag's range is the predicate.
	local sha
	sha=$(git rev-parse HEAD) # the v0.0.2 tip, which names no issue at all
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-9  In Review -> Done"* ]]
}

@test "a commit shipped by an EARLIER tag is not new in this one" {
	# The range is \"new in this tag\", so an ancestor of the previous tag has
	# already been reported once. Reporting it again on every later tag would
	# make the sweep noisier the longer the history gets.
	local sha
	sha=$(git rev-parse v0.0.1)
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" != *"CLOUD-9"* ]]
}

@test "a commit the tag does not contain is not movable" {
	local sha
	sha=$(git rev-parse HEAD)
	# v0.0.1 predates HEAD, so HEAD is not contained in it.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\"}]' | '$TASK' v0.0.1"
	[ "$status" -eq 0 ]
	[[ "$output" != *"CLOUD-9"* ]]
}

@test "a commit does not buy a way past the hold" {
	# A second way to be FOUND must not become a way around being HELD.
	local sha
	sha=$(git rev-parse HEAD)
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\",\"description\":\"DO-NOT-CLOSE\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-9  HELD"* ]]
}

@test "an unknown or malformed commit is ignored, not fatal" {
	# Supplementary evidence: a sha this clone cannot resolve must not take the
	# whole report down, or one stale payload field breaks every sweep.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"not-a-sha\"},{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" != *"CLOUD-9"* ]]
}

@test "an issue matched BOTH ways is reported once" {
	# The ordinary case for work that carries its ref and supplies a commit.
	local sha
	sha=$(git rev-parse HEAD)
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[ "$(grep -c 'CLOUD-2  In Review -> Done' <<<"$output")" -eq 1 ]
	[[ "$output" == *"1 to move"* ]]
}

@test "a payload with no commit field behaves exactly as before" {
	# The whole existing corpus pipes payloads without one; adding a second path
	# must cost them nothing.
	run bash -c "printf '%s' '$(payload CLOUD-2:In\ Review)' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" == *"1 to move"* ]]
}

@test "a tag naming no issue still reports cleanly when no commit matches either" {
	# The no-refs path used to exit BEFORE stdin was read, which would have made
	# commit matching unreachable for exactly the releases that need it most —
	# a tag of pure chore commits. Its clean-outcome contract is unchanged.
	commit "chore: release v0.0.3"
	git tag v0.0.3
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}]}]' | '$TASK' v0.0.3"
	[ "$status" -eq 0 ]
	[[ "$output" == *"references no CLOUD-* issue"* ]]
}

@test "a chore-only tag still matches an issue by commit" {
	# The half the moved early-exit unlocks: a release whose commits name nothing
	# can still move an issue whose commit it contains.
	commit "chore: release v0.0.3"
	git tag v0.0.3
	local sha
	sha=$(git rev-parse HEAD)
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-9\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/1\"}],\"commit\":\"$sha\"}]' | '$TASK' v0.0.3"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-9  In Review -> Done"* ]]
}

@test "a tag that does not exist is exit 2, not an empty release" {
	run "$TASK" v9.9.9
	[ "$status" -eq 2 ]
}

@test "stdin that is not a payload set is exit 2, distinct from a stale board" {
	run bash -c "printf 'not json' | '$TASK' v0.0.2"
	[ "$status" -eq 2 ]
}

# --- the conjunction: graph-check first (CLOUD-309) ---------------------------
#
# The hold marker catches an issue that SAYS it is not done. Nothing caught an
# issue that never started — CLOUD-228 and CLOUD-231 sat In Review with no PR ever
# attached and this task named both movable, because one commit merely cited them.

@test "THE SECOND REFUSAL: an In Review issue with no PR is REFUSED, not movable" {
	# The exact shape of CLOUD-228/231. Fails against the pre-fix ordering, where
	# the same payload reported `In Review -> Done` and exited 0.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  REFUSED"* ]]
	[[ "$output" != *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" == *"0 to move"* ]]
}

@test "the refusal names the rule that rejected it, not a generic failure" {
	# Pointer-only, and actionable: a caller must be able to tell an unlanded
	# issue from a held one without reading either body.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[]}]' | '$TASK' v0.0.2"
	[[ "$output" == *"in-review-no-pr"* ]]
}

@test "the same issue WITH a PR attachment still sweeps" {
	# The other direction, so the conjunction cannot collapse into refusing
	# everything — which would be the vacuous pass in refusal's clothing.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/9\"}]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
	[[ "$output" != *"REFUSED"* ]]
}

@test "a non-PR attachment is not a linked PR" {
	# graph-check's predicate is a github pull URL; a design doc link must not
	# clear it, or the gate is bypassed by attaching anything at all.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://example.com/notes\"}]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"REFUSED (in-review-no-pr)"* ]]
}

@test "a refused issue does not suppress the movable ones beside it" {
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[]},{\"id\":\"CLOUD-3\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/9\"}]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  REFUSED"* ]]
	[[ "$output" == *"CLOUD-3  In Review -> Done"* ]]
	[[ "$output" == *"1 to move"* ]]
	[[ "$output" == *"1 REFUSED"* ]]
}

@test "HELD and REFUSED are both reported, so one refusal never hides the other" {
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[],\"description\":\"x\"},{\"id\":\"CLOUD-3\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/9\"}],\"description\":\"DO-NOT-CLOSE\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2  REFUSED"* ]]
	[[ "$output" == *"CLOUD-3  HELD"* ]]
	[[ "$output" == *"1 HELD"* ]]
	[[ "$output" == *"1 REFUSED"* ]]
}

@test "the gate only judges In Review — a Done issue with no PR is left alone" {
	# Done is past this transition. Refusing there would report on a move the
	# sweep is not making.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"Done\",\"attachments\":[]}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"left alone"* ]]
	[[ "$output" != *"REFUSED"* ]]
}

@test "COULD NOT LOOK: an In Review payload with no attachments KEY is exit 2" {
	# The hazard CLOUD-309 names. `attachments` absent and `attachments: []` look
	# identical to the board gate, and both readings of that are wrong: refuse and
	# a correct sweep is blocked by how the caller fetched; allow and the gate is
	# vacuous exactly when it matters. So it is neither verdict — it is 2.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-2"* ]]
	[[ "$output" == *"attachments"* ]]
}

@test "a missing key on an issue this transition does not touch is not exit 2" {
	# The 2 is scoped to the question being asked. A Done issue's attachments are
	# never read, so demanding them would fail sweeps for no gain.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"Done\"}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
}

@test "a blocker outside the piped set is NOT a refusal" {
	# `dangling-blocker` is a property of the piped SET, not of the issue: a sweep
	# pipes the In Review closure by design, so an edge leaving it is the expected
	# input shape. Refusing on it would cost more than it saves on every ordinary
	# sweep, and a refusal that expensive gets bypassed.
	run bash -c "printf '%s' '[{\"id\":\"CLOUD-2\",\"status\":\"In Review\",\"attachments\":[{\"url\":\"https://github.com/o/r/pull/9\"}],\"relations\":{\"blockedBy\":[{\"id\":\"CLOUD-999\"}]}}]' | '$TASK' v0.0.2"
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2  In Review -> Done"* ]]
}

@test "the ordering is composed, not copied — no second in-review-no-pr predicate" {
	# §1: graph-check owns \"honestly labelled\". This task must name the rule in a
	# report and nowhere else; a `test(\"github.com/.*/pull/\")` here would be the
	# copy that drifts.
	run grep -c 'pull/' "$TASK"
	[ "$output" -eq 0 ]
}

@test "the marker is stated once, in the task, not spread across issue prose" {
	# One authority for the token (§1): an issue adds a hold by copying a string
	# the task defines, rather than inventing a phrasing the task must recognise.
	run grep -c "^HOLD_MARKER=" "$TASK"
	[ "$output" -eq 1 ]
}
