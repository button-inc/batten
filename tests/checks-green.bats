#!/usr/bin/env bats
# subject: mise-tasks/checks-green.sh
# The one definition of "is this SHA green" (CLOUD-346), exercised through the
# injected reading so every case runs offline — no `gh`, no stub, no network.
#
# $CI_REQUIRED_CHECKS is deliberately NOT set here. It arrives from mise.toml
# [env] via `mise run test:bats`, so these cases run against the real roster
# rather than a copy of it that could disagree with the one landing uses. The
# check names below are that roster's; `ci-local-parity` is what keeps it
# matching the workflows.

setup() {
	GREEN="$BATS_TEST_DIRNAME/../mise-tasks/checks-green.sh"
	export SHA=deadbeef
}

# A reading is TSV: status, conclusion, name, started_at, id — the shape
# `ci-wait` already holds after its conditional poll, and the shape the task
# fetches for itself. The last two order a name's runs (CLOUD-436); the cases
# that predate them are deliberately left three-field, since answering a
# reading with no ordering key exactly as before is itself a property.
runs() { printf '%s\n' "$@"; }

# The seven roster names for which ABSENCE is NOT a legitimate reading
# (CLOUD-337) — $CI_REQUIRED_CHECKS minus $CI_ABSENT_OK_CHECKS — all green, with
# whatever rows the case names appended after them. Any case whose subject is
# something OTHER than presence has to carry them now: a reading that omits one
# answers "no run at all" and exit 3 before it ever reaches the bucket the case
# is about, so it would pass on the wrong branch or hang the poll in `ci-wait`.
#
# Written with an ordering key at the floor of the day and ids 1..7, so a row a
# case supplies for the same name is NEWER and supersedes it under CLOUD-436's
# latest-per-name rule. That is what lets the supersession cases below compose
# with this helper without their own subject being decided here.
# DERIVED FROM THE ROSTER, never hand-listed. The set above was written out by
# name, which made it a SECOND copy of `$CI_REQUIRED_CHECKS` — and the header
# says as much, describing it as the roster minus the absent-ok names. Adding
# `perf` (CLOUD-172) proved the copy drifts: six cases here failed at once, and
# the same hand-listing in `tests/ci-wait.bats` did worse, hanging that suite
# instead of failing it, because a poll cannot tell a missing name from a run
# still going. Derived, the fixture is correct for whatever the roster says
# today, and the count in the comment above can never be wrong either.
mandatory_green() {
	local rows=() name i=0
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		i=$((i + 1))
		rows+=("completed	success	$name	2026-08-12T00:00:00Z	$i")
	done < <(tr ',' '\n' <<<"${CI_REQUIRED_CHECKS:?the suite runs under mise, which supplies the roster}" |
		grep -vxF -f <(tr ',' '\n' <<<"${CI_ABSENT_OK_CHECKS:-}") || true)
	# Anti-vacuity: an empty derived set would make every case that composes with
	# this helper pass while asserting nothing.
	[ "${#rows[@]}" -gt 0 ] || {
		echo "mandatory_green derived an empty set from CI_REQUIRED_CHECKS" >&2
		return 1
	}
	runs "${rows[@]}" "$@"
}

@test "a graded, all-success required set is green" {
	# The whole roster present and green — the reading a PR touching `action.yml`
	# produces, that being the one path in BOTH path filters, so `zizmor` and
	# `action` grade here rather than being legitimately absent. Its partner is
	# the CLOUD-327 row further down, which is this set minus exactly those two:
	# between them they fix that the exemption is a tolerance of absence and
	# never a discount on a name that did run.
	CHECKS_GREEN_RUNS="$(mandatory_green \
		"completed	success	zizmor	2026-08-12T00:00:00Z	8" \
		"completed	success	action	2026-08-12T00:00:00Z	9")" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"success"*"ci"* ]]
	[[ "$output" == *"every required check terminal and green"* ]]
}

@test "a partial set on a fresh SHA is not an answer (CLOUD-337)" {
	# THE DISCRIMINATING ROW: this exited 0 before the fix. `commit-lint` is a
	# git-log walk that grades in seconds while `ci`, `cross`, `msrv`, `semver`,
	# `darwin-link` and `final` are still queueing, so a reading of exactly one
	# graded check is the ORDINARY state of a freshly pushed SHA, not a corner
	# case. The old `if (!(name in bestkey)) continue` made every unregistered
	# name invisible, so the roster was answered by whichever check happened to
	# be quickest, and `land` posted /fast-forward into a branch protection
	# still listing the other six as expected — the bot was rejected (#280).
	CHECKS_GREEN_RUNS="$(runs "completed	success	commit-lint")" run "$GREEN"
	[ "$status" -eq 3 ]
	# Roster order, and the tolerated names elided from it — the output is a
	# contract (house style §6), so the list is asserted as a whole rather than
	# name by name.
	#
	# LITERAL ON PURPOSE, unlike `mandatory_green` above. Deriving this expectation
	# would compare the roster against itself and assert nothing about the message;
	# what is under test here is the ORDER and the elision, which only a written-out
	# list can pin. So a roster change must edit this line — and that is the sensor
	# working, not drift: it fails with a diff naming the missing entry, where a
	# derived fixture that silently went short is what hung `ci-wait`.
	# The roster shrank on 2026-08-21 (CLOUD-398 slice 2): `cross`,
	# `darwin-link`, `semver` and `windows` moved to `rust.yml` behind a
	# workflow-level `paths:` filter, so they are absent rather than skipped on a
	# diff they cannot judge and they joined `CI_ABSENT_OK_CHECKS`. A tolerated
	# name with no run is elided here for the same reason `zizmor` always was.
	# This line editing is the sensor working, exactly as the note above says.
	[[ "$output" == *"with no run at all: ci, perf, final"* ]]
	[[ "$output" != *"zizmor"* ]]
	# The four are elided too, and asserted by name: eliding them is the whole of
	# what the move bought, and a roster that quietly listed them again would
	# reopen the hang `CI_ABSENT_OK_CHECKS` exists to prevent.
	[[ "$output" != *"cross"* ]]
	[[ "$output" != *"darwin-link"* ]]
	[[ "$output" != *"semver"* ]]
	[[ "$output" != *"windows"* ]]
}

@test "a failure outranks a name that has not registered (CLOUD-337)" {
	# A GUARD-RAIL, not a discriminator: this PASSED before the fix, because a
	# name with no run was invisible then and there was no bucket for it to lose
	# to. It pins the ordering the fix introduces — the missing-name exit 3
	# fires only when the failed list is EMPTY — and the asymmetry with the
	# cancelled bucket above is the whole reason it needs pinning. A cancelled
	# sibling can MANUFACTURE a fan-in failure (`final` needs: the others, #293),
	# so no-verdict precedes red there; an absent name manufactures nothing, so
	# a completed failure beside it is an independent verdict on this tree and
	# must still re-draft the PR. Holding the poll open for the stragglers would
	# leave a ready PR over a tree already known to be red, buying a runner a lap
	# to re-learn it.
	CHECKS_GREEN_RUNS="$(runs "completed	failure	ci")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci failure"* ]]
	[[ "$output" != *"no run at all"* ]]
}

@test "an all-skipped required set is not an answer" {
	# The draft-era runs look terminal and unfailed. Treating them as an answer
	# would clear a PR whose CI never ran — and with the release PR now a draft
	# by default, this is the state on every refresh, not a corner case.
	CHECKS_GREEN_RUNS="$(runs "completed	skipped	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"required check(s) with no verdict"* ]]
	[[ "$output" == *"ci skipped"* ]]
}

@test "a cancelled required check is not an answer either, and says which word" {
	# CLOUD-363. A cancelled run judged nothing — it is the absence of an answer,
	# exactly like the draft-era skip. Reading it as red is what wedged #293: the
	# lap stopped, and nothing it could do afterwards created another check-run.
	# The conclusion is named beside the check because "no verdict" now has two
	# spellings, and a stall you cannot spell is a stall you cannot diagnose.
	CHECKS_GREEN_RUNS="$(runs "completed	cancelled	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"required check(s) with no verdict"* ]]
	[[ "$output" == *"ci cancelled"* ]]
}

@test "one cancelled required check is not redeemed by another that succeeded" {
	# The partial set, which is the ordinary shape of a supersession: whichever
	# legs had already finished carry their verdict, and the rest were killed
	# mid-run. Green would land a SHA most of whose checks never judged it.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci" \
		"completed	cancelled	cross")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"cross cancelled"* ]]
}

@test "a fan-in failing over cancelled upstreams is no verdict, not a red one" {
	# THE MEASURED SET, from #293 (CLOUD-363). `final` is a fan-in over the
	# others, so its failure is a CONSEQUENCE of the cancellations rather than an
	# independent judgement on the tree. This is why "no answer" is tested before
	# "red": promoting the failure here would report the whole set as a real
	# failure and put the branch straight back into the wedge.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	failure	final" \
		"completed	cancelled	msrv" \
		"completed	cancelled	ci" \
		"completed	cancelled	cross" \
		"completed	cancelled	darwin-link (aarch64-apple-darwin)" \
		"completed	cancelled	commit-lint")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" != *"not green"* ]]
}

@test "third-party successes do not make a draft-era skip set an answer" {
	# The set that landed #261 (CLOUD-327): every check that judges this
	# repository is a draft-era `skipped`, and the two workflows that are not
	# draft-gated graded on their own.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis" \
		"completed	success	release-plz" \
		"completed	skipped	commit-lint" \
		"completed	skipped	cross" \
		"completed	skipped	ci" \
		"completed	skipped	final" \
		"completed	skipped	darwin-link (aarch64-apple-darwin)")" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a required check still pending is not an answer" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis" \
		"in_progress	-	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"still running"* ]]
}

@test "an empty reading is not an answer, and takes no network to say so" {
	# Explicitly empty means "this SHA carries no check-run yet" — a real state,
	# and one that must not fall through to a fetch.
	CHECKS_GREEN_RUNS="" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a required check that failed is red, and named" {
	# CLOUD-363's second acceptance clause: making a cancellation recoverable
	# must not make a real failure recoverable. A failure with nothing ungraded
	# beside it leaves that bucket empty and falls through to exit 1.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci" \
		"completed	failure	cross")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not green"* ]]
	[[ "$output" == *"cross failure"* ]]
}

@test "a third-party check gets neither a vote nor a veto" {
	# Branch protection enforces the required set, so a failure outside it must
	# not hold `main`.
	CHECKS_GREEN_RUNS="$(mandatory_green \
		"completed	failure	SonarCloud Code Analysis" \
		"completed	skipped	release-plz")" run "$GREEN"
	[ "$status" -eq 0 ]
}

@test "an absent path-filtered check is not a skipped one (CLOUD-327)" {
	# `zizmor` and the `action` job produce no check-run AT ALL on a PR touching
	# neither a workflow, `action.yml`, nor the fixture corpus, because both
	# their workflows are paths-filtered. Requiring them to be PRESENT would
	# hang the ordinary PR forever, so $CI_ABSENT_OK_CHECKS names them.
	#
	# This row used to prove that with a lone `ci` success standing in for the
	# whole roster — which asserted the CLOUD-337 BUG rather than the CLOUD-327
	# exemption: it passed because a reading of one graded check answered for
	# nine, so it would have gone on passing with the exemption deleted. Stated
	# now the way it is implemented: the seven mandatory names present and
	# green, and exactly the two tolerated names missing.
	CHECKS_GREEN_RUNS="$(mandatory_green)" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every required check terminal and green"* ]]
}

@test "an unset required set is fatal rather than an empty one" {
	# An empty set makes every check unrequired, which is the false green this
	# task exists to stop — so it must not be reachable by forgetting a variable.
	CHECKS_GREEN_RUNS="$(runs "completed	skipped	ci")" run env -u CI_REQUIRED_CHECKS "$GREEN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"CI_REQUIRED_CHECKS is unset"* ]]
}

@test "CLOUD-376: an unset ANSWERED set is fatal for the same reason" {
	# An empty answered set makes every conclusion an answer, which is the same
	# false green in a new spelling — so the second shared manifest is guarded
	# exactly as strictly as the first.
	CHECKS_GREEN_RUNS="$(runs "completed	skipped	ci")" run env -u CI_ANSWERED_CONCLUSIONS "$GREEN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"CI_ANSWERED_CONCLUSIONS is unset"* ]]
}

@test "CLOUD-376: AN UNKNOWN CONCLUSION HOLDS THE POLL OPEN — it is not red" {
	# The case neither task could express before, and the one that proves the
	# catch-all is gone. Red used to be defined by NEGATION: anything completed
	# that was not skipped/cancelled/success/neutral fell through to a failure. So
	# a conclusion GitHub adds tomorrow — `stale` here — would be reported as a
	# verdict against a head nothing had judged, costing a re-draft and a lap.
	#
	# Not in $CI_ANSWERED_CONCLUSIONS now means "no answer": the poll continues,
	# which is recoverable. Fail safe, in the direction this repo has repeatedly
	# paid for getting backwards.
	CHECKS_GREEN_RUNS="$(mandatory_green "completed	stale	ci	2026-08-12T01:00:00Z	99")" run "$GREEN"
	[ "$status" -eq 3 ]
	# Assert the VERDICT, not the word. A `!= *"red"*` test can never pass here:
	# every "no answer" line says "requi-red check(s)", so the row was red on the
	# commit that introduced it and stayed red — a discriminator that cannot
	# discriminate, on the very change that added the mutation harness. Red is a
	# specific line and a specific status, so name both.
	[[ "$output" != *"is not green"* ]]
	[[ "$output" == *"no verdict: ci stale"* ]]
}

@test "CLOUD-376: a known bad conclusion is still red — the anti-vacuity half" {
	# Without this pair the change above could be "treat everything as no answer",
	# which never reports a failure at all and would hang every red branch in the
	# poll. `timed_out` is in the answered set and is not green.
	CHECKS_GREEN_RUNS="$(mandatory_green "completed	timed_out	ci	2026-08-12T01:00:00Z	99")" run "$GREEN"
	[ "$status" -eq 1 ]
}

# --- one name, one answer: the latest run (CLOUD-436) ------------------------
#
# A SHA accumulates a check-run per event, and a draft-created PR mints a whole
# skipped set from its `opened` event that never goes away. These cases fix
# which of a name's runs speaks for it.

@test "a skip superseded by a success is green — the residue does not veto the verdict" {
	# #342 and #345: readied without a push, the graded set landed beside the
	# draft-era skips on the same SHA, and the union read it as no answer. The
	# poll ran unbounded over a head whose every required check was green.
	#
	# The helper carries the other six mandatory names (CLOUD-337) and a third
	# `ci` run at the floor of the day, which BOTH rows below supersede — so the
	# verdict on `ci` is still decided by this pair and nothing else, and a
	# regression to union-per-name would put the skip back in the way and turn
	# this red.
	CHECKS_GREEN_RUNS="$(mandatory_green \
		"completed	skipped	ci	2026-08-12T03:18:10Z	93999182343" \
		"completed	success	ci	2026-08-12T03:20:16Z	93999484435")" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every required check terminal and green"* ]]
	# The summary is the judged view, so it cannot contradict the verdict.
	[[ "$output" != *"skipped"* ]]
}

@test "a skip superseded by a FAILURE is red — the case that made this urgent" {
	# #343: the poll could not see a completed failure, so the red that
	# re-drafts the PR never fired and the lap spent its wait learning nothing.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci	2026-08-12T02:50:00Z	1" \
		"completed	failure	ci	2026-08-12T02:55:00Z	2")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci failure"* ]]
}

@test "a success superseded by a skip is NOT an answer — the draft economy survives" {
	# The other direction, and the reason this is latest-per-name rather than
	# best-per-name: re-drafting a PR mints a fresh skip, and that skip is the
	# current state of the name. Answering green from a superseded success is
	# exactly the false green CLOUD-247/327 exist to stop.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T01:00:00Z	1" \
		"completed	skipped	ci	2026-08-12T02:00:00Z	2")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"required check(s) with no verdict"* ]]
}

@test "the id breaks a tie between two runs started in the same second" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T03:00:00Z	10" \
		"completed	skipped	ci	2026-08-12T03:00:00Z	11")" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a pending re-run supersedes a completed one — the answer is not in yet" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T03:00:00Z	1" \
		"in_progress	-	ci	2026-08-12T03:05:00Z	2")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"still running"* ]]
}

@test "each name is judged on its own latest, never one name's run against another's" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci	2026-08-12T03:00:00Z	1" \
		"completed	success	ci	2026-08-12T03:10:00Z	2" \
		"completed	success	cross	2026-08-12T03:01:00Z	3" \
		"completed	skipped	commit-lint	2026-08-12T03:11:00Z	4")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"commit-lint"* ]]
	[[ "$output" != *"skipped: ci"* ]]
}

@test "a reading with no ordering key answers as the union did — fail closed" {
	# The legacy three-field shape. Two runs of one name cannot be ordered, so
	# the least conclusive wins: this must never become green by accident.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci" \
		"completed	success	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "PRESSURE: a name with THREE runs on one SHA is judged by its latest" {
	# CLOUD-436 grades each name by its latest run, and the two-run case is
	# covered above. This is the shape the landing loop actually produces once a
	# transient is re-run (CLOUD-483): the draft-era skip, the red that never
	# reached a verdict, and the re-run that did — three runs, one name, and only
	# the third is an answer. Judged by the union, or by the first, or by any
	# rule that stops at two, this reads as red and re-drafts a healthy PR.
	CHECKS_GREEN_RUNS="$(mandatory_green \
		"completed	skipped	ci	2026-08-12T01:00:00Z	10" \
		"completed	failure	ci	2026-08-12T02:00:00Z	20" \
		"completed	success	ci	2026-08-12T03:00:00Z	30")" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every required check terminal and green"* ]]
}

@test "PRESSURE: three runs whose LATEST is red is still red" {
	# The anti-vacuity half. A rule that always took the greenest of N runs would
	# pass the row above and launder every failure that follows a success.
	CHECKS_GREEN_RUNS="$(mandatory_green \
		"completed	success	ci	2026-08-12T01:00:00Z	10" \
		"completed	skipped	ci	2026-08-12T02:00:00Z	20" \
		"completed	failure	ci	2026-08-12T03:00:00Z	30")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"is not green"* ]]
}
