#!/usr/bin/env bats
# The pull-time half of the board discipline (CLOUD-230).
#
# `issue-guard` proves an issue was looked up *at some point*; it fires on `gh pr
# create`, which is the end of the work. This is the check that belongs at the
# start, and the failure it encodes is measured: CLOUD-49 went In Progress at
# 04:29:34 and a second session started writing it about six minutes later,
# throwing the result away. The board carried the claim the whole time.
#
# Every case is a crafted payload, because the whole point of the
# agents-fetch-gates-decide contract is that the verdict is a pure function of
# stdin — no tracker credential, no network, nothing to stub.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/claim-check"
	# OUTSIDE ANY CLONE by default, which is what the header above claims these
	# cases are: a pure function of stdin. They were not — cwd was whatever the
	# runner was invoked from, i.e. this repository, so every pullable case minted
	# a real claim receipt into the developer's own `.git` as a side effect, and
	# CLOUD-431's session-stamp rule would now read that clone's stamp too. The
	# receipt cases below `cd` into a fixture clone deliberately; everything else
	# belongs nowhere.
	cd "$BATS_TEST_TMPDIR" || return 1
}

# A get_issue payload with the fields this gate reads. `description` and
# `updatedAt` joined the set with CLOUD-431: the gate now asks whether the story
# is refined and WHEN it was refined, and neither is answerable from a projection.
#
# `updatedAt` defaults to the epoch, which is "refined long before any session" —
# the ordinary, legitimate case, so a case only says otherwise when that is its
# subject.
#
# The Ready block is INLINE rather than a sibling helper, and that is not taste:
# every case reaches this through `bash -c "$(declare -f payload); …"`, which
# carries exactly the functions it names. A second helper would silently be
# undefined in that subshell, the description would arrive empty, and every case
# would fail at `not-ready` — measured, while writing this. One function, one
# `declare -f`, no way to forget the other.
#
# Minimal and synthetic rather than quoted from a real issue: the point is a
# body that `ready-lint` accepts, and a fixture quoting a live issue rots the
# moment that issue is groomed.
payload() {
	local block
	block=$(
		cat <<-'MD'
			**Refinement — Ready**

			* **Source of truth (§1).** The fixture's own body, which is all this case reads.
			* **Mechanism as a computable predicate (§2).** A gate resolves it to an exit code.
			* **Output & exit (§5).** Pointer-only, byte-stable.
			* **Commit / bump (§6).** `fix(fixture)` → **patch** until `0.1.0`.
			* **Test obligation (§7).** The bats case below.
			* **Blockers (§8).** None.
		MD
	)
	jq -nc \
		--arg id "${1:-CLOUD-1}" \
		--arg status "${2:-Todo}" \
		--arg assignee "${3:-}" \
		--arg pr "${4:-}" \
		--arg description "${5:-$block}" \
		--arg updated "${6:-1970-01-01T00:00:00.000Z}" \
		'{
      id: $id,
      status: $status,
      assignee: (if $assignee == "" then null else $assignee end),
      attachments: (if $pr == "" then [] else [{url: $pr}] end),
      description: $description,
      updatedAt: $updated
    }'
}

@test "a Todo issue with nobody on it is pullable" {
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | $CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pullable"* ]]
}

@test "the pullable message says to claim it, because the automation will not" {
	# The whole diagnosis in one line: the transition fires on the PR event, so
	# an agent that waits for it has already done the work.
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | $CHECK"
	[[ "$output" == *"before you write code"* ]]
	[[ "$output" == *"PR event"* ]]
}

@test "an issue already In Progress is not pullable" {
	run bash -c "$(declare -f payload); payload CLOUD-49 'In Progress' a@b | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 not-todo (in In Progress)"* ]]
}

@test "In Review and Done are not pullable either" {
	for state in "In Review" Done; do
		run bash -c "$(declare -f payload); payload CLOUD-49 '$state' | $CHECK"
		[ "$status" -eq 1 ]
		[[ "$output" == *"not-todo"* ]]
	done
}

@test "a Todo issue someone has already assigned is flagged" {
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo a@b | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 assigned"* ]]
}

@test "a Todo issue with a PR already attached is flagged, with the PR number" {
	# The case the column alone misses: someone published before the board moved.
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo '' https://github.com/button-inc/batten/pull/145 | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 has-pr (145)"* ]]
}

@test "a non-PR attachment is not a claim" {
	# Issues carry design docs and links; only a pull request means published work.
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo '' https://linear.app/buttoninc/document/x | $CHECK"
	[ "$status" -eq 0 ]
}

@test "output is pointer-only — the issue id and the rule, never a body" {
	run bash -c "$(declare -f payload); payload CLOUD-49 'In Progress' | $CHECK"
	[[ "$output" != *"description"* ]]
	[[ "$output" != *"Why"* ]]
}

@test "a set of issues is judged as a set, and one bad apple blocks" {
	run bash -c "$(declare -f payload); { payload CLOUD-230 Todo; payload CLOUD-49 'In Progress'; } | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 not-todo"* ]]
	[[ "$output" != *"CLOUD-230 not-todo"* ]]
}

@test "a JSON array is accepted as well as a stream, matching graph-check" {
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | jq -s '.' | $CHECK"
	[ "$status" -eq 0 ]
}

@test "unreadable stdin is exit 2, distinct from a failing check" {
	run bash -c "printf 'not json' | $CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not a set of get_issue payloads"* ]]
}

@test "empty stdin is exit 2, not a silent pass" {
	# A gate that reports pullable over nothing is the false green this repo
	# keeps re-meeting: an empty pipe must never read as permission.
	run bash -c "printf '' | $CHECK"
	[ "$status" -eq 2 ]
}

@test "a payload missing status is unreadable rather than assumed Todo" {
	run bash -c "echo '{\"id\":\"CLOUD-1\"}' | $CHECK"
	[ "$status" -eq 2 ]
}

# --- the claim receipt (CLOUD-272) ------------------------------------------
#
# `claim-check` was a pure read: it answered "is this pullable" and left no
# trace, so nothing downstream could tell a claimed branch from an unclaimed
# one. The receipt is that answer made durable, and `claim-guard` is its only
# reader.

setup_repo() {
	REPO="$BATS_TEST_TMPDIR/claimed"
	mkdir -p "$REPO"
	git -C "$REPO" init -q -b work
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m seed
	RECEIPT="$REPO/$(git -C "$REPO" rev-parse --git-dir)/batten-receipts/claim.work"
	# CLOUD-431: a fixture clone stands in for a session that has STARTED, which
	# is what `.claude/hooks/session-start.sh` records. Without it every case
	# would refuse at `no-session-stamp` and none of them would be testing what it
	# names. The cases that are ABOUT the stamp set its mtime deliberately.
	STAMP="$REPO/$(git -C "$REPO" rev-parse --git-dir)/batten-receipts/session-start"
	mkdir -p "$(dirname "$STAMP")"
	: >"$STAMP"
}

@test "the pullable path mints a receipt for the current branch" {
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-272 Todo | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPT" ]
	# It records WHICH issue was cleared, so the trace is auditable rather than
	# a bare flag.
	[[ "$(cat "$RECEIPT")" == *"CLOUD-272"* ]]
}

@test "a NOT-pullable issue mints nothing — the receipt is the claim, not the attempt" {
	for state in "In Progress" "In Review" Done; do
		setup_repo
		run bash -c "$(declare -f payload); payload CLOUD-49 '$state' | (cd '$REPO' && $CHECK)"
		[ "$status" -eq 1 ]
		[ ! -f "$RECEIPT" ]
	done
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo a@b | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPT" ]
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo '' https://github.com/o/r/pull/7 | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPT" ]
}

@test "unreadable stdin mints nothing either" {
	setup_repo
	run bash -c "printf 'not json' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 2 ]
	[ ! -f "$RECEIPT" ]
}

@test "outside a checkout the verdict still stands — the receipt is a side effect" {
	# The gate's answer must not depend on being in a repo: `graph-check` and
	# this compose in one pipeline, and a caller inspecting the board from
	# anywhere still deserves the verdict.
	run bash -c "$(declare -f payload); payload CLOUD-272 Todo | (cd '$BATS_TEST_TMPDIR' && $CHECK)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pullable"* ]]
}

# --- the refinement sequence (CLOUD-431) -------------------------------------
#
# The three rules above all detect a COMPETITOR, and every one of them reads
# "clear" when nobody else is involved — so they are blind by construction to a
# SOLE agent moving too fast. Measured on CLOUD-427, 2026-08-12: an agent asked
# to discuss a design instead filed the issue, wrote its own Ready block, moved
# it Todo, piped a payload it had hand-written to this gate, took the receipt,
# and implemented ~600 lines. Every guard that fired gated the SHAPE of an
# action; none gated the SEQUENCE.
#
# The stamp stands in for `.claude/hooks/session-start.sh`, whose whole job here
# is to record WHEN the session began.

# An unrefined body: prose, no Ready block, which is what `ready-lint` refuses
# with `no-ready-block`.
UNREFINED='## Why

Something is broken and someone should fix it.'

# `updatedAt` in the future relative to the stamp — i.e. refined AFTER this
# session started, which is the incident's shape.
refined_after_the_stamp() {
	date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null ||
		date -u -v+1H +%Y-%m-%dT%H:%M:%S.000Z
}

@test "THE INCIDENT REPLAY: an issue refined inside this session is refused at the claim" {
	setup_repo
	local later
	later=$(refined_after_the_stamp)
	run bash -c "$(declare -f payload); payload CLOUD-427 Todo '' '' '' '$later' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-427 refined-this-session"* ]]
	[ ! -f "$RECEIPT" ]
}

@test "the legitimate path is not prompted, delayed or refused" {
	# The property AGENTS.md's autonomous-workflow section protects. A block that
	# passes lint and was written in an EARLIER session is pullable with no
	# ceremony — both new rules are silent on it, which is what keeps this a gate
	# on the sequence rather than a gate on autonomy.
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pullable"* ]]
	[ -f "$RECEIPT" ]
	[[ "$output" != *"refined-this-session"* ]]
	[[ "$output" != *"not-ready"* ]]
}

@test "a block ready-lint refuses mints no receipt" {
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-1 Todo '' '' '$UNREFINED' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 not-ready"* ]]
	[ ! -f "$RECEIPT" ]
}

@test "the refusal is pointer-only — the rule id, never the block it read" {
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-1 Todo '' '' '$UNREFINED' | (cd '$REPO' && $CHECK)"
	[[ "$output" != *"Something is broken"* ]]
	[[ "$output" != *"someone should fix it"* ]]
}

@test "a missing session stamp REFUSES rather than passing" {
	# A gate that silently clears everything it cannot see is the false green
	# this repo keeps re-meeting. Inside a clone the sequence question is
	# answerable, so being unable to answer it is a refusal.
	setup_repo
	rm -f "$STAMP"
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-session-stamp"* ]]
	[ ! -f "$RECEIPT" ]
}

@test "a payload that cannot date its own refinement is refused" {
	# The field is emptied on an OTHERWISE VALID payload, because `payload`'s
	# `${6:-default}` cannot express "present but empty" and a hand-built payload
	# would fail at `not-ready` first — testing the wrong rule while looking like
	# it tested this one.
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | jq -c '.updatedAt = \"\"' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-updated-at"* ]]
	[ ! -f "$RECEIPT" ]
}

@test "an UNPARSEABLE timestamp is exit 2, not a verdict about the story" {
	# The distinction the whole exit table rests on: "this story was refined too
	# recently" and "I could not read the date at all" are different answers, and
	# collapsing the second into the first would convict a payload whose only
	# defect is a format nobody here can parse.
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo '' '' '' 'not-a-timestamp' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not compare"* ]]
	[ ! -f "$RECEIPT" ]
}

@test "the bypass mints a receipt in BOTH refused cases, and says so" {
	# The hatch is a human's visible decision, so it is loud. It is also its own
	# variable: `BATTEN_CLAIM_GUARD_BYPASS` says "do not refuse my edit", which is
	# a different decision from "mint a receipt for a story refined just now".
	setup_repo
	local later
	later=$(refined_after_the_stamp)
	run bash -c "$(declare -f payload); payload CLOUD-427 Todo '' '' '' '$later' | (cd '$REPO' && BATTEN_CLAIM_CHECK_BYPASS=1 $CHECK)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPT" ]
	[[ "$output" == *"BATTEN_CLAIM_CHECK_BYPASS set"* ]]

	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-1 Todo '' '' '$UNREFINED' | (cd '$REPO' && BATTEN_CLAIM_CHECK_BYPASS=1 $CHECK)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPT" ]
}

@test "the receipt records the verdict and the revision it was taken against" {
	# Widened from a bare id list: a human debugging a refusal otherwise has to
	# reconstruct which revision the claimant had in front of them. Line 1 keeps
	# the id list exactly where it was, so any reader that parsed it still works.
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 0 ]
	local body
	body=$(cat "$RECEIPT")
	[[ "$(head -n1 "$RECEIPT")" == "CLOUD-230" ]]
	[[ "$body" == *"ready-lint pass"* ]]
	[[ "$body" == *"claimed-at "* ]]
	[[ "$body" == *"updated-at CLOUD-230 1970-01-01T00:00:00.000Z"* ]]
	# Pointer-only: keys, a verdict word and timestamps, never the block.
	[[ "$body" != *"Refinement"* ]]
}

@test "a bypassed claim says so IN the receipt, not only on stderr" {
	# stderr is not retained; the receipt is. A claim taken under the hatch must
	# still be auditable weeks later.
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-1 Todo '' '' '$UNREFINED' | (cd '$REPO' && BATTEN_CLAIM_CHECK_BYPASS=1 $CHECK)"
	[[ "$(cat "$RECEIPT")" == *"ready-lint bypassed"* ]]
}
