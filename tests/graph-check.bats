#!/usr/bin/env bats
# subject: mise-tasks/graph-check.sh
# graph-check's decision table (CLOUD-175): the two board predicates from
# mem:workflow/board-states as exit codes, graph coherence, and the frontier as
# a by-product. Fixtures are get_issue-shaped payloads built with jq.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/graph-check.sh"
	BOARD="$BATS_TEST_TMPDIR/board.json"
	# EVERY CASE RUNS IN A THROWAWAY REPO, because the gate now mints the
	# board-move receipt CLOUD-512's guard reads. Run from this checkout, the
	# suite wrote adjudications into the real `.git/batten-receipts/` — receipts
	# that would authorise a live session's moves to In Review over fixture ids.
	# Measured on the first green run of the new rows.
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	cd "$REPO" || return 1
	RECEIPTS="$REPO/.git/batten-receipts"
	# ONE PASSING READY BLOCK, shared by `issue` and `describe`. Since CLOUD-375 a
	# Todo issue whose block fails ready-lint is a violation, so a fixture body is
	# never neutral: a bare-prose description makes every Todo case a
	# `todo-not-ready` run, whatever rule it meant to exercise. Lifting the block
	# out is what lets a case choose — carry it and be judged on something else,
	# or omit it deliberately, as the CLOUD-375 rows below do.
	READY="**Refinement — Ready (t)**

* **Source of truth (§1).** One artifact."
}

# issue <id> <status> [assignee] [pr-url] [blocker...] — appends one payload.
issue() {
	local id="$1" status="$2" assignee="${3:-}" pr="${4:-}"
	shift 4 || shift $#
	local rel="[]"
	if [ "$#" -gt 0 ]; then
		rel=$(printf '%s\n' "$@" | jq -R '{id: .}' | jq -sc .)
	fi
	local att="[]"
	[ -n "$pr" ] && att=$(jq -nc --arg u "$pr" '[{url: $u}]')
	# `statusType` IS DERIVED FROM THE COLUMN, not passed, because Linear returns
	# both on every payload and a fixture carrying only one is not the shape the gate
	# reads (CLOUD-477). The mapping is the live board's, verified 2026-08-23 — and
	# the pair that matters is that `Canceled` is `canceled` while `Duplicate` is
	# `duplicate`, two distinct values, not one shared canceled type.
	local ty
	case "$status" in
	Todo) ty=unstarted ;;
	Backlog) ty=backlog ;;
	"In Progress" | "In Review") ty=started ;;
	Done) ty=completed ;;
	Canceled) ty=canceled ;;
	Duplicate) ty=duplicate ;;
	*) ty="" ;;
	esac
	jq -nc --arg id "$id" --arg st "$status" --arg a "$assignee" \
		--arg ready "$READY" --arg ty "$ty" \
		--argjson att "$att" --argjson rel "$rel" '{
		id: $id, status: $st, attachments: $att,
		relations: {blockedBy: $rel},
		description: ("**Why**\nx.\n\n" + $ready),
		projectMilestone: {id: "m-1", name: "Phase 3"}
	} + (if $a == "" then {} else {assigneeId: $a} end)
	  + (if $ty == "" then {} else {statusType: $ty} end)' >>"$BOARD"
}

# The same payload with `projectMilestone` omitted — which is how Linear renders
# an issue that has none, since it drops the key rather than nulling it. Separate
# from `drop_key`, which strips the field from EVERY issue and so models the other
# case entirely: a caller that projected it away (CLOUD-695).
no_milestone() {
	issue "$@"
	jq -c --arg id "$1" 'if .id == $id then del(.projectMilestone) else . end' \
		"$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

check() { run bash -c "'$CHECK' <'$BOARD'"; }
# stdout alone, for the cases that pin the frontier's bytes rather than a report.
check_out() { run bash -c "'$CHECK' <'$BOARD' 2>/dev/null"; }

# Drop a key from every payload in the board — the projection a caller makes when
# it fetches without includeRelations, or assembles the set by hand.
drop_key() {
	jq -c "del(.$1)" "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

# describe <id> <text> — give one issue a body to be judged on. The Ready block
# rides along: these fixtures are about what the PROSE claims, and a claim written
# as bare prose would be refused as `todo-not-ready` before its own rule was ever
# reached — the case would then pass or fail on the wrong verdict.
describe() {
	jq -c --arg id "$1" --arg d "$2

$READY" 'if .id == $id then .description = $d else . end' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

@test "a coherent board exits 0" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"board coherent (2 issues)"* ]]
}

@test "an unassigned In Progress issue is reported" {
	issue CLOUD-1 "In Progress" "" ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 in-progress-unassigned"* ]]
}

@test "an assigned In Progress issue is not" {
	issue CLOUD-1 "In Progress" someone ""
	check
	[ "$status" -eq 0 ]
}

@test "an In Review issue with no PR attachment is reported" {
	issue CLOUD-1 "In Review" someone ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 in-review-no-pr"* ]]
}

@test "an In Review issue with a linked PR is not" {
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	check
	[ "$status" -eq 0 ]
}

# ─── CLOUD-735: a row that declares it lands no commit ───────────────────────
#
# `in-review-no-pr` keys on an artifact a dispatch record never produces, and
# `done-check` refuses a Done no tag reaches, so both gates out of In Progress are
# unreachable by construction for a commitless row. Three sat In Progress with
# their campaigns finished — CLOUD-607, 632, 703 — indistinguishable on the board
# from work someone abandoned.
#
# The declaration is §6's, which `ready-lint` already parses and now emits, so
# these cases carry a real §6 clause rather than a flag this gate invented.
declares_none() { # declares_none <id> <status> [pr-url]
	issue "$1" "$2" someone "${3:-}"
	jq -c --arg id "$1" '
		if .id == $id
		then .description += "\n* **Commit / bump (§6).** **none** — this row lands no commit."
		else . end' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

@test "AN IN REVIEW ROW DECLARING NO COMMIT IS EXEMPT FROM in-review-no-pr" {
	declares_none CLOUD-1 "In Review"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"in-review-no-pr"* ]]
}

# THE ANTI-CHEAT, and without it `none` becomes the cheapest way past this gate
# for any row at all — the roster cheat CLOUD-607 names, one layer over.
@test "a row declaring no commit that carries a PR is refused for the contradiction" {
	declares_none CLOUD-1 "In Review" "https://github.com/o/r/pull/9"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 declares-no-commit-with-pr"* ]]
}

# THE ARM MUST NOT WIDEN. A row that says nothing about §6 is judged exactly as it
# was, which is what keeps the exemption a declaration rather than a default.
@test "an In Review row that declares nothing is still refused with no PR" {
	issue CLOUD-1 "In Review" someone ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 in-review-no-pr"* ]]
}

# AND IT IS SCOPED TO In Review. A Todo row declaring `none` is a normal queue
# entry; reading the declaration anywhere else would be a second predicate.
@test "a declaration of no commit does not change how any other column is judged" {
	declares_none CLOUD-1 Todo
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"declares-no-commit-with-pr"* ]]
}

@test "a blockedBy cycle is reported with its members" {
	issue CLOUD-1 Todo "" "" CLOUD-2
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"blockedby-cycle"* ]]
	[[ "$output" == *"CLOUD-1"* && "$output" == *"CLOUD-2"* ]]
}

@test "a dangling blocker is reported" {
	# CLOUD-678 MOVED THIS ARM FROM exit 1 TO exit 2, and the case is rewritten
	# rather than deleted. It asserted that a blocker outside the piped closure is
	# a board signalling falsely; measured, it is a closure that cannot answer the
	# question — Linear keeps `blockedBy` after the blocker completes, so an
	# active-only closure carries such an edge for every landed blocker and this
	# fired on correct boards routinely. It is also set-keyed now, like
	# `unjudgeable-blockedby`, so `released`'s `refusal_for` cannot see it.
	issue CLOUD-1 Todo "" "" CLOUD-99
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph dangling-blocker (CLOUD-99)"* ]]
	[[ "$output" != *"CLOUD-1 dangling-blocker"* ]]
}

# --- CLOUD-634: the joins are indexed, and the index is built once -------------
#
# Verdict parity is asserted by every OTHER case in this file staying green — that
# is the point of not moving them. This case is the load-bearing half: parity alone
# passes on the unmodified task, so a change that did nothing would still go green
# without a bound on the work.
#
# The bound is against the EDGE count, which is the row's own wording. A per-issue
# content scan (the status-claim arm) grows with the ISSUE count and is not a join,
# so the fixture pair below holds the issue count fixed and varies only the edges.

# Counts execs of $1 by putting a counting wrapper ahead of it on PATH.
count_execs() { # count_execs <tool> ; sets COUNT
	local tool=$1 bin="$BATS_TEST_TMPDIR/wrap"
	mkdir -p "$bin"
	local real
	real=$(command -v "$tool")
	: >"$BATS_TEST_TMPDIR/$tool.count"
	cat >"$bin/$tool" <<WRAP
#!/usr/bin/env bash
echo x >>"$BATS_TEST_TMPDIR/$tool.count"
exec "$real" "\$@"
WRAP
	chmod +x "$bin/$tool"
	PATH="$bin:$PATH" run bash -c "'$CHECK' <'$BOARD'"
	COUNT=$(grep -c x "$BATS_TEST_TMPDIR/$tool.count" || true)
}

# THE DEPENDENTS MUST BE `Todo`, and that is not cosmetic: the frontier loop is
# the only place an EDGE is walked, and it walks one only for a Todo row. A fixture
# whose rows are all Done adds edges that nothing traverses, so the jq arm passed
# before the index too — measured, and it is exactly the non-discriminating case
# CLOUD-418 is about. The `ready-lint` fork per Todo id stays and is constant
# across both arms, because both carry the same three Todo rows.
few_edges() {
	: >"$BOARD"
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	issue CLOUD-3 Todo "" ""
	issue CLOUD-4 Todo "" ""
}
many_edges() {
	: >"$BOARD"
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	issue CLOUD-3 Todo "" "" CLOUD-1 CLOUD-2
	issue CLOUD-4 Todo "" "" CLOUD-1 CLOUD-2 CLOUD-3
}

@test "the jq count does not grow with the edge count" {
	# One edge, then six over the same four rows. `status_of` ran a fresh `jq` over
	# the whole payload array per edge endpoint, so this arm was strictly larger
	# before the index.
	few_edges
	count_execs jq
	local few=$COUNT
	[ "$few" -gt 0 ]

	many_edges
	count_execs jq
	[ "$COUNT" -eq "$few" ]
}

@test "the grep count does not grow with the edge count" {
	# `in_set` ran once per edge and the adjacency scan once per node; both are
	# parameter expansion now, so neither reaches `grep` at all.
	few_edges
	count_execs grep
	local few=$COUNT

	many_edges
	count_execs grep
	[ "$COUNT" -eq "$few" ]
}

# --- CLOUD-678: a blocker outside the piped set is a question nobody asked -----
#
# `status_of` is a `jq` select over the payloads, so an id not in the set came back
# as the empty string and fell into the resolve loop's catch-all — turning "I was
# not given this blocker" into "this blocker has not completed". Measured on
# `b2f8992` over real payloads for CLOUD-672 and CLOUD-674, whose only blocker had
# been Done since the night before: no frontier lines at all.

@test "a Todo issue whose only blocker is Done and piped reaches the frontier" {
	# The unchanged half, pinned so the fix cannot buy the arm below by breaking
	# the ordinary case.
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
}

@test "a blocker outside the piped set is unjudgeable, not resolved" {
	# THE ARM. Exit 2 and an `unjudgeable`-family line naming the blocker, never a
	# silent frontier omission — which is what made this invisible, since
	# `excluded (blocked-by …)` reads identically to a legitimate block.
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-2 excluded (unjudgeable-blocker CLOUD-1)"* ]]
	[[ "$output" != *"frontier CLOUD-2"* ]]
	# NOT the scheduling note: that reads as "this is legitimately blocked", which
	# is the wrong remedy. The caller's next action is a re-fetch.
	[[ "$output" != *"CLOUD-2 excluded (blocked-by"* ]]
}

@test "a piped, genuinely open blocker still excludes at exit 0" {
	# Unchanged, attribution intact: an unlanded blocker is scheduling, and the
	# issue is not claiming otherwise.
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 excluded (blocked-by CLOUD-1)"* ]]
	[[ "$output" != *"unjudgeable-blocker"* ]]
}

# --- CLOUD-477: a blocker that will never be done does not block ---------------
#
# The frontier resolved a blocker by column NAME — `Done` or `In Review` — so every
# other column fell into the catch-all and blocked. Two of those are TERMINAL, and
# both mean "this work will never be done, and that is settled", so the dependent
# was starved off the frontier permanently with no path back but a human noticing.
# The exclusion even printed as `excluded (blocked-by …)`, indistinguishable from a
# legitimate block, which is what kept it invisible.

@test "a Todo row whose only blocker is Canceled reaches the frontier" {
	issue CLOUD-1 Canceled "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
	[[ "$output" != *"CLOUD-2 excluded (blocked-by"* ]]
}

@test "a Todo row whose only blocker is Duplicate reaches the frontier" {
	# THE ARM THE ROW'S OWN §1 WOULD HAVE MISSED. It says the payload carries "a
	# canceled type covering both Canceled and Duplicate". Measured, it does not:
	# `Duplicate` is its own `duplicate` type. A rule keyed on `canceled` alone
	# passes the case above and leaves this one starving — half the defect, and it
	# would have shipped looking complete.
	issue CLOUD-1 Duplicate "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
}

@test "a blocker In Review still resolves, since its type is started" {
	# THE GUARD AGAINST A TYPE-ONLY REWRITE, which is the obvious simplification and
	# is wrong: `In Review` carries `started`, the same type `In Progress` carries,
	# so resolving on type alone would starve every row behind landed-but-unreleased
	# work. The name arm has to stay.
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/1"
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
}

@test "an In Progress blocker still excludes, with its attribution unchanged" {
	# The other direction (CLOUD-418): a rule that resolved everything would be an
	# outage, not a fix. `In Progress` shares `started` with `In Review`, so this is
	# also what proves the name arm is narrow rather than a blanket pass on `started`.
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 excluded (blocked-by CLOUD-1)"* ]]
	[[ "$output" != *"frontier CLOUD-2"* ]]
}

@test "a Backlog blocker still excludes" {
	issue CLOUD-1 Backlog "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 excluded (blocked-by CLOUD-1)"* ]]
}

@test "a frontier row over a retired blocker says so" {
	# CLOUD-477's second decision, made rather than assumed: resolving a retired
	# blocker is right for the FRONTIER and not obviously right for the WORK, since
	# an issue whose blocker was cancelled may have had its premise cancelled with
	# it. So the row is schedulable and the reason is on the record — a `note`, so
	# the exit code does not move.
	issue CLOUD-1 Canceled "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 frontier-over-retired-blocker CLOUD-1"* ]]
}

@test "a frontier row over a COMPLETED blocker says nothing extra" {
	# The note must be narrow: an ordinary landed blocker is not a premise question,
	# and noting it would train readers to ignore the line.
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
	[[ "$output" != *"retired-blocker"* ]]
}

@test "a set with no edges at all is unchanged by the three-way branch" {
	issue CLOUD-1 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-1"* ]]
	[[ "$output" != *"unjudgeable-blocker"* ]]
	[[ "$output" != *"dangling-blocker"* ]]
}

@test "one row short of its closure does not withhold the rest of the frontier" {
	# The measured shape, minimised: the active-only closure CLOUD-607 prescribes.
	# CLOUD-3 is fully judgeable and must still be offered — the exit code says the
	# set was short, and the frontier still carries what could be decided.
	issue CLOUD-2 Todo "" "" CLOUD-1
	issue CLOUD-3 Todo "" ""
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"frontier CLOUD-3"* ]]
	[[ "$output" != *"frontier CLOUD-2"* ]]
}

@test "the frontier is unblocked lint-passing Todo issues" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	issue CLOUD-3 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
	[[ "$output" == *"frontier CLOUD-3"* ]]
}

@test "a Todo issue blocked by unfinished work is off the frontier" {
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"frontier CLOUD-2"* ]]
}

@test "a blocker landed to In Review unblocks its dependents" {
	# Trunk-based: In Review means the code is on main, so a dependent can build.
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-2"* ]]
}

# --- CLOUD-375: Todo is a column claim, and an unready queue entry falsifies it -
#
# The measured shape: three issues promoted Backlog -> Todo in one pass, two of
# them failing ready-lint, and this gate reporting `board coherent` over the
# closure that held them. Both were caught by a session running ready-lint by
# hand, which is discipline rather than a mechanism.

@test "a Todo issue with no Ready block is refused" {
	issue CLOUD-1 Todo "" ""
	# Overwrite its description with one carrying no Ready block at all.
	jq -c '.description = "just prose"' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 todo-not-ready"* ]]
	# Still off the frontier: the refusal is added to the exclusion, not swapped
	# for it — a caller reading the frontier must not be offered it either.
	[[ "$output" != *"frontier CLOUD-1"* ]]
}

@test "a Todo issue whose Ready block satisfies the clauses is not" {
	# ANTI-VACUITY, and the load-bearing half: a rule that fired on every Todo
	# issue would pass the deny case above while making the gate unusable.
	issue CLOUD-1 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"frontier CLOUD-1"* ]]
	[[ "$output" != *"todo-not-ready"* ]]
}

@test "a Backlog issue with no Ready block is not refused" {
	# Backlog makes no claim, so there is nothing to falsify — the non-goal
	# asserted rather than assumed. A gate failing every ungroomed issue anywhere
	# in a piped closure would stop being piped.
	issue CLOUD-1 Backlog "" ""
	jq -c '.description = "just prose"' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-not-ready"* ]]
	[[ "$output" == *"board coherent"* ]]
}

@test "wip counts In Progress only" {
	issue CLOUD-1 "In Progress" a ""
	issue CLOUD-2 "In Review" b "https://github.com/o/r/pull/1"
	issue CLOUD-3 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"wip 1"* ]]
}

@test "output ordering is byte-stable and numeric" {
	issue CLOUD-10 Todo "" ""
	issue CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 0 ]
	first=$(grep -n "frontier CLOUD-2$" <<<"$output" | cut -d: -f1)
	second=$(grep -n "frontier CLOUD-10$" <<<"$output" | cut -d: -f1)
	[ "$first" -lt "$second" ]
}

@test "an array input works the same as a stream" {
	issue CLOUD-1 Todo "" ""
	jq -sc . "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 0 ]
}

@test "unparseable stdin exits 2, not 1" {
	echo "not json" >"$BOARD"
	check
	[ "$status" -eq 2 ]
}

# --- CLOUD-251: an exclusion is attributable, and "could not look" is exit 2 ---
#
# The regression these pin: `|| continue` collapsed ready-lint's exit 1 and exit
# 2 into one silent absence, so "this is not Ready" and "you did not pipe me
# enough to judge it" were byte-identical, and a set whose relations the caller
# projected away was reported an acyclic, non-dangling board.

@test "an unjudgeable payload and a failing Ready block do not produce the same output" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	cp "$BOARD" "$BATS_TEST_TMPDIR/base.json"
	# One run with CLOUD-2's description key absent…
	jq -c 'if .id == "CLOUD-2" then del(.description) else . end' "$BATS_TEST_TMPDIR/base.json" >"$BOARD"
	unreadable=$(bash -c "'$CHECK' <'$BOARD' 2>&1" || true)
	# …and one where the same issue's Ready block genuinely fails.
	jq -c 'if .id == "CLOUD-2" then .description = "just prose" else . end' "$BATS_TEST_TMPDIR/base.json" >"$BOARD"
	failing=$(bash -c "'$CHECK' <'$BOARD' 2>&1" || true)
	[ "$unreadable" != "$failing" ]
	# Both still exclude it: what differs is the reason, not the frontier.
	[[ "$unreadable" != *"frontier CLOUD-2"* ]]
	[[ "$failing" != *"frontier CLOUD-2"* ]]
}

@test "a payload ready-lint cannot read is reported and exits 2" {
	issue CLOUD-1 Todo "" ""
	drop_key description
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-1 excluded (unjudgeable-ready-block)"* ]]
	[[ "$output" != *"board coherent"* ]]
	# "I could not read what you piped" is never collapsed into CLOUD-375's
	# violation: exit 2 asks for a re-fetch, exit 1 asks for the board to be fixed,
	# and answering the second over an unread payload sends the caller to the wrong
	# repair.
	[[ "$output" != *"todo-not-ready"* ]]
}

@test "a genuinely failing Ready block is attributed and refused" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 todo-not-ready"* ]]
	# ready-lint's own rule id, forwarded rather than re-derived — and still
	# pointer-only, so the body it judged never reaches the log.
	[[ "$output" == *"CLOUD-1:0 no-ready-block"* ]]
	[[ "$output" != *"$secret"* ]]
	# Its ::error:: summary is still dropped: one verdict gets one summary, and
	# this gate prints its own violation count.
	[[ "$output" != *"not Ready"* ]]
}

@test "a Todo issue held off the frontier by a blocker says which one" {
	issue CLOUD-1 "In Progress" someone ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-2 excluded (blocked-by CLOUD-1)"* ]]
}

@test "a set carrying no blockedBy data claims nothing about the graph" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-blockedby (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"board coherent"* ]]
}

@test "the missing-blockedBy report is keyed to the set, not to each issue" {
	# released's refusal_for greps this stderr for `^<id> <rule>`, so a per-id
	# line would turn every In Review issue in a relations-free sweep into a
	# REFUSED. The property is of the piped set, exactly like dangling-blocker.
	issue CLOUD-1 "In Review" someone "https://github.com/o/r/pull/9"
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-blockedby (CLOUD-1)"* ]]
	[[ "$output" != *"CLOUD-1 unjudgeable"* ]]
}

@test "an explicit empty blockedBy is data, not an unjudgeable payload" {
	issue CLOUD-1 Todo "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"unjudgeable"* ]]
}

@test "a payload it could not read outranks a board it could" {
	issue CLOUD-1 "In Progress" "" ""
	issue CLOUD-2 Todo "" ""
	jq -c 'if .id == "CLOUD-2" then del(.description) else . end' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	# Both report sets print; the code says "re-fetch", not "fix your board".
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-1 in-progress-unassigned"* ]]
	[[ "$output" == *"CLOUD-2 excluded (unjudgeable-ready-block)"* ]]
}

@test "a judgeable, passing board emits no exclusion and no unjudgeable report" {
	# Anti-vacuity: the new reports must not decay into ones that always fire.
	# A real edge, so the graph claims are judged rather than absent.
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" "" CLOUD-1
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"excluded"* ]]
	[[ "$output" != *"unjudgeable"* ]]
	[[ "$output" == *"board coherent"* ]]
}

@test "a coherent set's stdout bytes are unchanged" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 Todo "" ""
	check_out
	[ "$status" -eq 0 ]
	[ "$output" = "wip 0
frontier CLOUD-2
graph-check: board coherent (2 issues)" ]
}

@test "violations are pointer-only — no issue prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 "In Progress" "" ""
	jq -c --arg s "$secret" '.description = $s' "$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}

# --- CLOUD-234: a status gloss is not a second authority for the board -------
#
# The measured shape: CLOUD-8's child inventory said "CLOUD-87 — **In Progress**
# (PR #157)" two seconds after CLOUD-87 completed and its PR merged. Every such
# block passed ready-lint at exit 0, because nothing checked a column word.

@test "a body claiming a column the board contradicts is reported" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 "Children:
* CLOUD-2 — **In Progress** (PR #157)"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"* ]]
}

@test "the same claim, agreeing with the board, is clean" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-2 — **Done**"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "a mention asserting no column is not a claim" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "Splits the representation CLOUD-2 introduced; see it for the rationale."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "Linear's stored mention markup is caught identically to the rendered form" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 '* <issue id="x" href="https://linear.app/i/CLOUD-2">CLOUD-2</issue> — **In Progress**'
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"* ]]
}

@test "a claim about an id outside the piped set is unjudgeable, never guessed" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-99 — **Done**"
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unjudgeable (CLOUD-1 claims CLOUD-99, not in the piped set)"* ]]
	# Keyed to the SET, not to the claiming issue: released's refusal_for greps
	# this stderr for `^<id> <rule>`, and which closure was piped is the caller's
	# choice, not that issue's dishonesty.
	[[ "$output" != *"CLOUD-1 status-claim-unjudgeable"* ]]
}

@test "a quoted or backticked citation of a claim is not a claim" {
	# Naming a claim is not making one — deferral-check's discipline, and the
	# reason this gate does not fail the very issue that ships it.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 'The inventory said "CLOUD-2 — **In Progress** (PR #157)" after it merged,
and the same defect in a span reads `CLOUD-2 — In Progress` too.'
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "narration about an issue is not a claim about its column" {
	# MEASURED, and the reason the connective is an allowlist. Over this repo's
	# own prose a length-bounded span with a `was|were` blocklist fired three
	# times, all wrong — these are two of them, and the blocklist that would fix
	# them has no end: went, sat, showed, landed.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	issue CLOUD-3 Done "" ""
	issue CLOUD-4 "In Progress" someone ""
	describe CLOUD-1 "CLOUD-2 went In Progress at 04:29 and CLOUD-3 still read In Progress.
CLOUD-2 was Done when this was written, then reopened."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "a gloss with no verb at all is a claim, in every shape the corpus uses" {
	# The complement of the row above: punctuation, emphasis, a table cell, or a
	# present-tense connective. Each must still be caught.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 Done "" ""
	issue CLOUD-4 Done "" ""
	issue CLOUD-5 "In Progress" someone ""
	describe CLOUD-1 "| CLOUD-2 | In Progress |
CLOUD-3 is In Progress
CLOUD-4 (now In Progress)"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 claimed In Progress, board says Done"* ]]
	[[ "$output" == *"CLOUD-3 claimed In Progress, board says Done"* ]]
	[[ "$output" == *"CLOUD-4 claimed In Progress, board says Done"* ]]
}

@test "a set with no descriptions cannot be scanned for claims, and says so" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	drop_key description
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-description (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"board coherent"* ]]
}

# CLOUD-526's accept row for this gate. The row above is the refusal half — a
# field this gate decides on is absent, so it says which and exits 2. This is the
# other half: a payload carrying ONLY the declared field set is accepted, with no
# unjudgeable report and no violation. Together they pin the contract from both
# sides, which is what stops the set drifting wider by accident.
#
# Unlike its three siblings, this gate genuinely reads the body — the §8 claim
# scan and the Ready-block delegation both consume it — so `description` is IN
# the set here. That asymmetry is the point of declaring the set per gate rather
# than once for all four.
@test "a set carrying only the declared field set is accepted" {
	jq -nc --arg ready "$READY" '{
		id: "CLOUD-1", status: "Todo",
		attachments: [], relations: {blockedBy: []},
		description: ("**Why**\nx.\n\n" + $ready),
		projectMilestone: {id: "m-1", name: "Phase 3"}
	}' >"$BOARD"
	# CLOUD-771 ADDED `projectMilestone` TO THIS ROW, and the change is the clause
	# widening rather than the declared field set moving. This fixture is an In
	# Progress row with no milestone — precisely the shape the widened clause now
	# refuses — so leaving it bare would make this case assert the OPPOSITE of
	# CLOUD-771's acceptance while claiming to be about the minimum payload.
	jq -nc '{
		id: "CLOUD-2", status: "In Progress", assigneeId: "someone",
		attachments: [], relations: {blockedBy: []},
		description: "nothing to claim here",
		projectMilestone: {id: "m-1", name: "Phase 3"}
	}' >>"$BOARD"
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"board coherent"* ]]
	[[ "$output" != *"unjudgeable"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
}

@test "a status claim report is pointer-only — no surrounding prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	describe CLOUD-1 "$secret: CLOUD-2 — **In Progress**"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"status-claim-disagrees"* ]]
	[[ "$output" != *"$secret"* ]]
}

@test "a column no piped issue occupies is not in the vocabulary" {
	# Stated rather than worked around. §1 forbids a second copy of the status
	# list, so the vocabulary is whatever the closure spells — the same way the
	# frontier is already relative to what was piped.
	#
	# CLOUD-838 gave the GLOSS form's silence a sibling that is not silent: the
	# same unspellable column, asserted with a present-tense connective, is
	# refused at exit 2 by the rows below. This shape stays exit 0 deliberately —
	# with no vocabulary to lean on, `— **In Review**` and `— **Batten**` are the
	# same bytes, and telling them apart needs the second authority §1 forbids.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	describe CLOUD-1 "* CLOUD-2 — **In Review**"
	check
	[ "$status" -eq 0 ]
}

# --- CLOUD-838: the alphabet's own anti-vacuity arm ---------------------------
#
# The scan's vocabulary is the piped set's OCCUPIED statuses, so a claim naming
# any other column never matched and the row passed silently — and a row that
# LEFT a column is exactly the row whose old column nothing in the set occupies.
# The predicate was weakest where it was most needed.

@test "a claim naming a column no piped issue occupies is refused, not ignored" {
	# Red before the arm: silent, exit 0.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"* ]]
	# Keyed to the SET, like status-claim-unjudgeable: which closure was piped is
	# the caller's choice, not this issue's dishonesty.
	[[ "$output" != *"CLOUD-1 status-claim-unscannable"* ]]
}

@test "the same claim, over a set that DOES occupy the column, is judged as before" {
	# The vocabulary can spell it now, so the existing exit-1 rule decides and the
	# new arm must stand down — one claim, one rule id, never both.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 Canceled "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement."
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 status-claim-disagrees (CLOUD-2 claimed Canceled, board says Done)"* ]]
	[[ "$output" != *"status-claim-unscannable"* ]]
}

@test "a body carrying a stale claim AND its own correction reports the stale one" {
	# CLOUD-743's real shape, measured 2026-08-21 and the case the whole row
	# exists for. The correction is in the vocabulary (`Todo` is occupied), so the
	# gate matched it, compared it against the board, and passed — satisfied by
	# the accurate half of a body whose other half was false.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now Canceled, on a measurement.

Note also that CLOUD-2 is Todo, not Canceled."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"* ]]
	# The correction agrees with the board, so nothing disagrees — which is
	# precisely why the row above alone does not pin this.
	[[ "$output" != *"status-claim-disagrees"* ]]
}

@test "ordinary prose is not a claim, however capitalized" {
	# The bound on false triggers, and both halves of it. A capitalized word with
	# no connective is a mention; a connective with no capital is narration.
	# Measured over this repo's whole tracked tree: the claim shape occurs six
	# times and every one is a real column claim.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 Batten's engine, per the note above.
CLOUD-2 is the durable artifact this campaign rests on.
Splits the representation CLOUD-2 introduced; see Regorus for the rationale."
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
}

@test "an unscannable report is pointer-only — no surrounding prose echoed" {
	local secret="ACME Corp escalation"
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "$secret: CLOUD-2 is now Canceled."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"status-claim-unscannable"* ]]
	[[ "$output" != *"$secret"* ]]
}

@test "a multi-word column is named whole, never its first word" {
	# `In` points at nothing a reader can act on. The span is capitalized WORDS,
	# because the columns it has to name are multi-word.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	describe CLOUD-1 "CLOUD-2 is now In Review."
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"claims CLOUD-2 is In Review"* ]]
}

@test "ANTI-VACUITY: a set with no status claims anywhere still exits 0" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	issue CLOUD-3 "In Progress" someone ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"status-claim"* ]]
	[[ "$output" == *"board coherent"* ]]
}

# --- the board-move receipt (CLOUD-512, per id since CLOUD-312 row 3) ---------
#
# ONE FILE PER JUDGED ID. It was a single `board-move` file carrying `<epoch> <id>
# <id> …` per run, read by a guard that grepped for the id. The engine's `named`
# receipt key is one file per subject, so the set is the set of FILES now — the
# same keying, asked of the filesystem instead of of a regex.

@test "a coherent board records one receipt per id it judged" {
	issue CLOUD-1 Done "" ""
	issue CLOUD-2 "In Review" "" "https://github.com/o/r/pull/1"
	check
	[ "$status" -eq 0 ]
	# The ids are the point: a bare "graph-check ran" receipt is satisfied by
	# judging one clean issue and then sweeping fifteen.
	[ -f "$RECEIPTS/board-move.CLOUD-1" ]
	[ -f "$RECEIPTS/board-move.CLOUD-2" ]
	# Field 1 is the epoch, kept for a human reading the store; the engine bounds
	# recency by the file's mtime.
	[[ "$(awk '{print $1}' "$RECEIPTS/board-move.CLOUD-1")" =~ ^[0-9]+$ ]]
	# And no aggregate is left behind, or two shapes would describe one fact.
	[ ! -f "$RECEIPTS/board-move" ]
}

@test "a value that is not an issue key mints nothing, so it cannot become a path" {
	# `ids` is `jq -r '.[].id'` over a payload from somewhere else, and the id
	# becomes a filename. A value the store cannot key is a subject nothing asks
	# about, which is the posture the retiring guard took.
	#
	# `notakey` rather than `../escaped`, and that is the discriminating choice: a
	# traversal is ALSO stopped by the filesystem (`board-move.CLOUD-1` is not a
	# directory, so the redirect fails), so a fixture built on one passes whether
	# the shape clause is there or not. Measured — CLOUD-418, and it caught a clause
	# in this file defending nothing.
	issue notakey Done "" ""
	check
	[ "$status" -eq 0 ]
	[ -z "$(find "$RECEIPTS" -name 'board-move*' 2>/dev/null)" ]
}

@test "a board signalling falsely records nothing" {
	# In Review with no PR attachment — the CLOUD-480 shape. A refusal that still
	# minted would authorise the very move it just refused.
	issue CLOUD-3 "In Review" "" ""
	check
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPTS/board-move.CLOUD-3" ]
}

@test "a board it could not read records nothing" {
	issue CLOUD-4 Done "" ""
	drop_key relations
	check
	[ "$status" -eq 2 ]
	[ ! -f "$RECEIPTS/board-move.CLOUD-4" ]
}

@test "an earlier closure stays judged, because each id has its own receipt" {
	# What "runs accumulate" meant when one file held every run: a second run must
	# not void the first id. Per-id files give that structurally, and the newest
	# adjudication of ONE id overwrites its own stale receipt rather than sitting
	# behind it — which is what makes the mtime the age the engine reads.
	issue CLOUD-5 Done "" ""
	check
	[ "$status" -eq 0 ]
	: >"$BOARD"
	issue CLOUD-6 Done "" ""
	check
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/board-move.CLOUD-5" ]
	[ -f "$RECEIPTS/board-move.CLOUD-6" ]
	[ "$(wc -l <"$RECEIPTS/board-move.CLOUD-6")" -eq 1 ]
}

@test "the receipt is pointer-only — an id and an epoch, never issue prose" {
	issue CLOUD-7 Done "" ""
	check
	[[ "$(cat "$RECEIPTS/board-move.CLOUD-7")" != *"Source of truth"* ]]
	[[ "$(cat "$RECEIPTS/board-move.CLOUD-7")" != *"Refinement"* ]]
}

# A receipt that cannot be written must not turn a coherent board into a failing
# one: this gate's verdict is about the board, never about the store.
@test "an unwritable receipt store does not change the verdict" {
	issue CLOUD-8 Done "" ""
	mkdir -p "$REPO/.git/batten-receipts"
	chmod 500 "$REPO/.git/batten-receipts"
	check
	chmod 700 "$REPO/.git/batten-receipts"
	[ "$status" -eq 0 ]
}

# --- todo-unmilestoned (CLOUD-695) -------------------------------------------
#
# Todo is the ready queue, so sitting in it claims the work is pullable — and
# pullable work has to say which phase it advances. Nothing asked for ~340
# issues. These four rows are the clause and its one real hazard: Linear OMITS
# `projectMilestone` when it is null, so per-issue the field's absence cannot be
# told from a caller who projected it away, and the discriminator is the set.
#
# Fixtures, never the live board: the sweep this clause exists to make permanent
# will clean the live board, and a case reading it would go green for the wrong
# reason and could never fail again.

@test "a Todo issue carrying a milestone is clean, and still reaches the frontier" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Done "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-unmilestoned"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
}

@test "a Todo issue with no milestone, in a set where others carry one, is refused" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 Todo "" ""
	check
	[ "$status" -eq 1 ]
	# `unmilestoned (<column>)` since CLOUD-771: the id named one column while the
	# clause covered three, which would read as a lie on an In Review row.
	[[ "$output" == *"CLOUD-2 unmilestoned (Todo)"* ]]
	# The judgeable one is not swept up with it, and the clause must not change
	# which issues are pullable.
	[[ "$output" != *"CLOUD-1 todo-unmilestoned"* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
	# Pointer-only: the id and the rule, never the body the fixture carries.
	[[ "$output" != *"**Why**"* ]]
}

@test "a set with the field absent everywhere is unjudgeable, not a wall of violations" {
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 Todo "" ""
	issue CLOUD-3 Done "" ""
	drop_key projectMilestone
	check
	# 2, not 1. Reporting these as violations is the CLOUD-679 shape — a finding
	# where the gate cannot look — and it would fire on every caller who projected
	# the field away.
	[ "$status" -eq 2 ]
	[[ "$output" == *"graph unjudgeable-milestone (CLOUD-1 CLOUD-2)"* ]]
	[[ "$output" != *"todo-unmilestoned"* ]]
	# Only the Todo ids: a Done issue carries no milestone claim to judge.
	[[ "$output" != *"CLOUD-3"* ]]
}

# --- CLOUD-771: the claim is gated in every started column, not just Todo -----
#
# The seam was at Todo, which is the column AGENTS.md instructs an agent to leave as
# fast as possible — so the compliant workflow was itself the escape. Measured:
# CLOUD-769 sat in the gated column for 138 seconds and left it unphased, and over
# the live board 20 unparented rows outside Todo carried no milestone (4 In Progress,
# 16 In Review) against 0 in Todo, which had been swept that day.

@test "an unparented In Progress row with no milestone is refused" {
	# THE DISCRIMINATOR, and the state twenty rows were in. Red against the
	# Todo-only clause.
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 "In Progress" someone ""
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 unmilestoned (In Progress)"* ]]
}

@test "an unparented In Review row with no milestone is refused" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 "In Review" someone "https://github.com/o/r/pull/9"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 unmilestoned (In Review)"* ]]
}

@test "a started row carrying a milestone passes, and its frontier place is unchanged" {
	# The other direction (CLOUD-418): a clause that refused every started row would
	# be an outage rather than a gate.
	issue CLOUD-1 Todo "" ""
	issue CLOUD-2 "In Progress" someone ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *unmilestoned* ]]
	[[ "$output" == *"frontier CLOUD-1"* ]]
}

@test "a parented row is reported ONCE, by CLOUD-599's clause and not CLOUD-771's" {
	# THE COMPOSITION ASSERTION, and the reason both rows belong in one bundle. The
	# two quantifiers partition rather than overlap: CLOUD-771 ranges over UNPARENTED
	# rows, CLOUD-599 over (child, parent) pairs where the child inherits the
	# parent's phase. Double-reporting would price one absence twice and make
	# whichever clause landed second read as a regression.
	#
	# Before CLOUD-599 landed this case asserted exit 0 — correct then, because
	# nothing owned the pair and 771 deliberately skips it. It now asserts the pair
	# is owned, which is the same claim from the other side.
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 "In Progress" someone ""
	jq -c 'if .id == "CLOUD-2" then . + {parentId: "CLOUD-1"} else . end' \
		"$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 child-unmilestoned (parent CLOUD-1)"* ]]
	# NOT by 771's clause: that id names a column, and seeing both would mean one
	# row paid twice for one missing field.
	[[ "$output" != *"CLOUD-2 unmilestoned ("* ]]
}

@test "a Done row with no milestone is clean — a closed row's phase changes nothing" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 Done "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *unmilestoned* ]]
}

@test "the anti-vacuity arm widened with the clause" {
	# A set holding ONLY started rows and no `projectMilestone` key anywhere must
	# read as projected-away, not as a wall of violations. Scoped to the Todo ids,
	# this arm would have gone quiet the moment the clause it guards grew — the stale
	# guard being the failure, in the direction that reports less.
	no_milestone CLOUD-1 "In Progress" someone ""
	no_milestone CLOUD-2 "In Review" someone "https://github.com/o/r/pull/9"
	drop_key projectMilestone
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"unjudgeable-milestone"* ]]
	[[ "$output" != *"CLOUD-1 unmilestoned"* ]]
}

# --- CLOUD-599: a child inherits its parent's phase, or declares otherwise ----
#
# "Is Phase 3 done" had two answers over two different sets and nothing reconciled
# them, so the milestone could read 100% with four issues its own epics parent
# still open. The decision is the row's: the epic tree is authoritative, and a
# re-phase must be DECLARED by carrying another milestone rather than by carrying
# none.
#
# EVERY CASE HERE IS A COMMITTED FIXTURE, never the live board, and §7 is explicit
# about why: the acceptance criterion REPAIRS the corpus this gate is written
# against, so a live-board case would go green for the wrong reason the moment the
# repair lands and could never fail again.

# A child of $2 carrying no milestone of its own.
child_no_milestone() { # child parent [status]
	no_milestone "$1" "${3:-Todo}" someone ""
	jq -c --arg c "$1" --arg p "$2" \
		'if .id == $c then . + {parentId: $p} else . end' \
		"$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

# A child of $2 carrying its own milestone $3 — the declared re-phase when it
# differs from the parent's. The clause decides on PRESENCE rather than identity
# (see its comment), so what this fixture establishes is that the child carries one
# at all; the id is here so the fixture reads like a real payload.
child_with_milestone() { # child parent milestone-id
	issue "$1" Todo "" ""
	jq -c --arg c "$1" --arg p "$2" --arg m "$3" \
		'if .id == $c then . + {parentId: $p, projectMilestone: {id: $m, name: $m}} else . end' \
		"$BOARD" >"$BOARD.2" && mv "$BOARD.2" "$BOARD"
}

@test "a child with no milestone under a milestoned parent is refused" {
	# THE SILENT CASE — all eight live instances, and the only arm where the
	# divergence is absent from the data rather than recorded in it. Red before the
	# clause landed.
	issue CLOUD-1 Todo "" ""
	child_no_milestone CLOUD-2 CLOUD-1
	check
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 child-unmilestoned (parent CLOUD-1)"* ]]
}

@test "a child carrying a DIFFERENT milestone is the declared re-phase and passes" {
	# THE ANTI-NUISANCE ARM, and four live rows depend on it — CLOUD-263 under
	# CLOUD-14 is genuinely Phase 4 work adopted by a Phase 3 epic. A gate that
	# refused this would be demanding the data be wrong.
	issue CLOUD-1 Todo "" ""
	child_with_milestone CLOUD-2 CLOUD-1 "phase-4"
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *child-unmilestoned* ]]
}

@test "a child whose parent carries no milestone is clean — no pair can diverge" {
	# The ordinary shape. Reporting it would make the clause fire on every row under
	# an unphased parent, which is an outage rather than a gate.
	no_milestone CLOUD-1 Todo someone ""
	child_no_milestone CLOUD-2 CLOUD-1
	# CLOUD-1 is unparented and unmilestoned, so CLOUD-771's clause owns it; the
	# assertion here is about the PAIR, so it reads the rule id rather than the code.
	check
	[[ "$output" != *child-unmilestoned* ]]
}

@test "a parent outside the piped set is unjudgeable, not a violation" {
	# CLOUD-678's discriminator, reused rather than re-derived: a closure that does
	# not carry the parent cannot answer, and guessing from its absence is exactly
	# the defect that row fixed one clause over. Exit 2, distinguishable from both a
	# clean board and a refusal.
	issue CLOUD-1 Todo "" ""
	child_no_milestone CLOUD-2 CLOUD-999
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-2 child-milestone-unjudgeable"* ]]
	[[ "$output" != *"CLOUD-2 child-unmilestoned"* ]]
}

@test "a Backlog issue with no milestone is clean — filing stays free" {
	issue CLOUD-1 Todo "" ""
	no_milestone CLOUD-2 Backlog "" ""
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"todo-unmilestoned"* ]]
	[[ "$output" != *"unjudgeable-milestone"* ]]
}
