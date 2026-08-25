#!/usr/bin/env bash
#MISE description="Gate: the board's dependency graph is coherent, and every started issue is honestly labelled (reads get_issue payloads on stdin; emits the ready frontier)"
#
# CLOUD-175. The board is the observability surface the whole workflow contract
# leans on, and its discipline was prose: an issue sitting in In Progress
# unassigned, or in In Review with nothing landed, is a false signal of exactly
# the kind Batten exists to catch. These are the two predicates
# mem:workflow/board-states names as the computable version of that discipline,
# plus the graph coherence the frontier depends on:
#
#   in-progress-unassigned   In Progress => assignee != null
#   in-review-no-pr          In Review   => at least one linked GitHub PR
#   todo-not-ready           Todo        => ready-lint over it exits 0
#   unmilestoned (<column>)  a STARTED, unparented row carries a projectMilestone
#                            — Todo, In Progress or In Review (CLOUD-771)
#   child-unmilestoned       a child of a MILESTONED parent carries a milestone
#                            of its own — the same one, or a different one
#                            declared; carrying none is the refusal (CLOUD-599)
#   declares-no-commit-with-pr  a row whose §6 declares `none` carries a PR
#                            anyway, so the declaration is false (CLOUD-735)
#   blockedby-cycle          the blockedBy relation is acyclic
#
# The third is CLOUD-375's, and it is a peer of the first two rather than a
# frontier note because `Todo` is a column CLAIM of the same kind: the board model
# defines it as the queue of issues whose Ready block is satisfied, so an unready
# issue sitting in it is the column signalling falsely. Measured: three issues
# were promoted Backlog -> Todo in one pass, two of them failing `ready-lint`, and
# this gate reported `board coherent (4 issues)` over the closure that held them.
# It emitted no frontier line either — an absence, which is what a queue is read
# THROUGH rather than something a reader notices.
#
# Two more vocabularies sit BESIDE those, at their own exit codes (CLOUD-251),
# because "the board is lying" is not the only thing this can find:
#
#   unjudgeable-blockedby        a payload carries no blockedBy key    -> exit 2
#   unjudgeable-milestone        no payload carries projectMilestone   -> exit 2
#   dangling-blocker             a blocker is outside the piped set    -> exit 2
#   excluded (unjudgeable-ready-block)  ready-lint could not read it   -> exit 2
#   excluded (unjudgeable-blocker …)  a blocker of THIS row is outside -> exit 2
#                                the piped set, so whether it is
#                                resolved is a question nobody asked
#   excluded (blocked-by …)      a blocker has not landed              -> exit 0
#   frontier-over-retired-blocker  a blocker resolved by being CANCELED
#                                or DUPLICATE rather than completed,
#                                so the premise may have gone with it -> exit 0
#
# `dangling-blocker` MOVED into this family from the violation list (CLOUD-678).
# Both of the arms above it are the same fact — a blocker outside the closure —
# and one of them was reporting a lying board while the other reported an
# unanswerable question. The decision and the rejected option are recorded beside
# the code rather than here.
#
# And one more predicate, CLOUD-234's: prose is not a second authority for a
# column, so a status the board decides is checked against the board.
#
#   status-claim-disagrees       a body asserts a column that is false -> exit 1
#   status-claim-unjudgeable     it asserts one about an unpiped id    -> exit 2
#   status-claim-unscannable     it asserts one in a column no piped   -> exit 2
#                                issue occupies, so the scan's own
#                                alphabet cannot spell it
#   unjudgeable-description      a payload carries no description key  -> exit 2
#
# ─── THIS FILE'S `CLOUD-[0-9]+` SITES ARE NOT RE-DERIVATIONS (CLOUD-806) ─────
#
# CLOUD-806 asked for `ready-lint` to emit the structure it builds and for this
# file's three re-derived issue-key regexes to be deleted. The emission landed and
# has a consumer; the deletion does not apply here, and the measurement is recorded
# so nobody spends a second attempt discovering it.
#
# Measured 2026-08-23 — this file derives the key at FIVE sites, not three, and not
# one of them rebuilds anything `ready-lint` computes:
#
#   the cycle report   ids out of `tsort`'s OUTPUT. Not a body at all; `ready-lint`
#                      never sees it and could not emit it.
#   the claim scan     `CLOUD-N is <Column>` over prose, twice, plus the CAPSPAN
#   (four sites)       arm. A predicate `ready-lint` does not implement, over the
#                      whole body rather than the §8 span.
#
# `ready-lint`'s own sites derive §8 blocker citations and deferral citations —
# different predicates over different spans. So the duplication CLOUD-806 names is
# of the REGEX LITERAL across nine spellings, which that row explicitly scopes out
# as CLOUD-761's, and not of the derivation. Deleting a site here would mean
# deleting a predicate, not a rebuild.
#
# DECLARED FIELD SET (CLOUD-526), stated because a gate that never writes its
# input contract down grows one by accident: `id` and `status` for every issue,
# `relations.blockedBy` for the graph, `description` for the §8 claim scan and
# the Ready-block delegation, `assignee` for In Progress and `attachments` for In
# Review. This gate is the one of the four that genuinely reads the body, so the
# projection CLOUD-526 buys elsewhere is not available here — and that is the
# whole reason each absence above is a NAMED exit-2 refusal rather than a rule
# that quietly scans nothing. Sending less must never buy a cleaner verdict.
# `projectMilestone` joins it with CLOUD-695, and it is the one field the tracker
# omits rather than nulls — which is why its absence is decided over the SET.
#
# The mutation demotes the milestone refusal to a note, which is the reading that
# let 174 open issues accumulate with no phase: visible in the output, invisible
# in the exit code, and therefore invisible to `verify` and CI.
# CLOUD-477's three arms, one per terminal column the name match could not see.
# Each targets a line carrying no `|`, because `mutant.sh` reads a declaration with
# `IFS='|'` and a pattern with its own pipe shifts every field after it.
#MUTANT canceled-blocker-still-starves|s@^\t\[\[ "$t" = canceled \]\] && return 0@\t:@|a Todo row whose only blocker is Canceled reaches the frontier
#MUTANT duplicate-blocker-still-starves|s@^\t\[\[ "$t" = duplicate \]\] && return 0@\t:@|a Todo row whose only blocker is Duplicate reaches the frontier
#MUTANT in-review-loses-its-name-arm|s@^\t\[\[ "$(status_of "$1")" = "In Review" \]\] && return 0@\t:@|a blocker In Review still resolves, since its type is started
#MUTANT retirement-is-silent|s@^\t\t\[\[ -z "$retired" \]\] .*@\t\t:@|a frontier row over a retired blocker says so
#MUTANT milestone-refusal-is-a-note|s@^\t\treport "\$id" "unmilestoned@\t\tnote "$id" "unmilestoned@|in a set where others carry one, is refused
# CLOUD-599's two arms, mutating in opposite directions. The first demotes the
# refusal to a note — the quiet direction, where the clause reports and decides
# nothing.
#MUTANT child-refusal-is-a-note|s@^\t\t\treport "\$id" "child-unmilestoned@\t\t\tnote "$id" "child-unmilestoned@|a child with no milestone under a milestoned parent is refused
# The second drops the `!= "null"` guard on the CHILD's milestone, so a child
# carrying a DIFFERENT milestone is refused too — the nuisance direction, and the
# arm four live rows depend on. Named a line with no `||` in it deliberately.
#MUTANT declared-rephase-refused|s@^\t\telif \[\[ "$(milestone_col_of "$parent")" = "set" \]\] .*@\t\telif [[ -n "$parent" ]]; then@|a child carrying a DIFFERENT milestone is the declared re-phase and passes
#
# CLOUD-838's arm takes the same directive, for the same reason one level down:
# demoted to a note the unscannable claim still prints and still exits 0, so the
# arm is visible in the output and invisible to `verify` and CI — which is the
# reading the row above records as having let 174 unmilestoned rows accumulate.
#MUTANT unscannable-refusal-is-a-note|s@^\t\tunjudged "graph" "status-claim-unscannable@\t\tnote "graph" "status-claim-unscannable@|a claim naming a column no piped issue occupies is refused
#
# "At least one linked PR attachment" is a deliberate approximation of "landed":
# it is checkable from the payload alone. Commit containment and "all referenced
# PRs merged" are release-gate questions and belong to the In Review -> Done
# transition, not this column check.
#
# On stdout, the by-product that makes the same command the scheduler: the READY
# FRONTIER — Todo issues whose Ready block passes ready-lint and whose blockers
# are all resolved (Done, or In Review: landed code is on main in a fast-forward
# trunk, so a dependent can build on it) — plus the build WIP count. Every agent
# computing this independently gets the same answer; that shared determinism is
# what replaces a dispatcher.
#
# Agents fetch, gates decide: the caller pipes get_issue(includeRelations: true)
# payloads (a stream or a JSON array) and this stays a pure function of stdin —
# no tracker credential, no network. Pipe the closure you want judged; an edge
# leaving the piped set is reported as dangling rather than guessed about.
#
# The mutation drops the ids from the receipt, leaving a bare "graph-check ran"
# that authorises any issue — the rubber stamp CLOUD-512's §2 rules out, and the
# shape the CLOUD-480 sweep would still have passed.
#MUTANT receipt-carries-no-ids|s@^	receipt_ids=.*@	receipt_ids=""@|a coherent board records which ids it judged
#
# The mutation demotes the Todo refusal back to a frontier note, which is exactly
# the state CLOUD-375 found: the id and the reason still printed, the exit code
# untouched, so the ready queue is judged by whoever reads the log. A case
# asserting the string but not the status would survive it.
#MUTANT todo-refusal-is-a-note|s@^		report "\$id" "todo-not-ready"@		note "$id" "todo-not-ready"@|a Todo issue with no Ready block is refused
#
# CLOUD-678's arm, and the mutation is the rewrite that removes the check while
# passing every other row: returning "resolved" for a blocker nobody piped. The
# `in_set` guard becomes vacuously true, the row reaches the frontier, and the
# question "is this blocker done" is answered by never having been asked.
#MUTANT absent-blocker-reads-as-resolved|s@^		if ! in_set "$to"; then@		if false; then@|a blocker outside the piped set is unjudgeable, not resolved
# CLOUD-735's two arms, and the second is the one that keeps the first honest.
# Dropping the exemption strands every commitless row In Progress again.
#MUTANT in-review-none-not-exempt|s/if \[\[ "$prs" = 0 \]\] && \[\[ "$declares_none" = 0 \]\]; then/if [[ "$prs" = 0 ]]; then/|DECLARING NO COMMIT IS EXEMPT
# Dropping the contradiction refusal makes `none` the cheapest way past this gate
# for any row at all, which is the roster cheat CLOUD-607 names.
#MUTANT declared-none-with-pr-passes|s/report "$id" "declares-no-commit-with-pr"/:/|a row declaring no commit that carries a PR is refused
set -euo pipefail

lint="$(dirname "$0")/ready-lint.sh"

# Accept either a JSON array or a concatenated stream of payload objects.
# Exit 2 is "unreadable input", distinct from a failing board.
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' 2>/dev/null) ||
	[[ "$(jq 'length' <<<"$issues")" = 0 ]] ||
	! jq -e 'all(.[]; has("id") and has("status"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: stdin is not a set of get_issue payloads (need id and status per issue)" >&2
	exit 2
fi

violations=0
unjudgeable=0
# Pointer-only per non-negotiable rule 4: issue id and rule id, never bodies.
report() {
	echo "$1 $2" >&2
	violations=$((violations + 1))
}
# CLOUD-251. Three channels, not one, because this script answers two different
# questions and used to collapse them into a single absence:
#
#   report()   the board is signalling falsely           -> exit 1
#   unjudged() the caller did not pipe enough to judge   -> exit 2
#   note()     an honest frontier exclusion              -> exit code unmoved
#
# A Todo issue whose Ready block fails is an unrefined issue, not an incoherent
# board, so it must never move the exit code — but it must still be attributable,
# which is the whole defect: "not Ready" and "not judgeable" were the same one
# missing `frontier` line and nothing else.
note() { echo "$1 $2" >&2; }
unjudged() {
	note "$1" "$2"
	unjudgeable=$((unjudgeable + 1))
}

# Byte-stable ordering everywhere: numeric by issue number.
by_num() { sort -t- -k2,2n; }

ids=$(jq -r '.[].id' <<<"$issues" | by_num)

# --- THE JOINS ARE INDEXED, AND THE INDEX IS BUILT ONCE (CLOUD-634) -----------
#
# These three lookups are the plumbing under every predicate below, and each used
# to be a linear rescan paid PER NODE OR PER EDGE rather than once per run:
# `status_of` ran a fresh `jq` over the WHOLE payload array to resolve one id and
# is called from four loops; `in_set` ran `grep -qxF` once per edge; adjacency ran
# `grep -E "^$id "` over the whole edge list inside the loop over every id, which
# is O(V·E) with a process per node.
#
# The board is small, which is why it never bit. What makes it worth fixing is
# WHERE this runs: every fan-out member computes the frontier independently,
# because that shared determinism is what replaces a dispatcher
# (`mem:workflow/agent-fanout`), so the cost is per session per member and grows
# with the board rather than with the work.
#
# It is an INDEXING defect in the plumbing, not an algorithmic one in the decision.
# Every genuinely graph-shaped step is already delegated to an exact tool — cycles
# to `tsort`, ancestry to `git merge-base --is-ancestor` — and none is at fault.
#
# ─── WHY PARAMETER EXPANSION AND NOT AN ASSOCIATIVE ARRAY ────────────────────
#
# `mise-tasks/**` must stay bash 3.2 and BSD portable: macOS ships bash 3.2, and
# `no-bash4-mapfile`, `no-bash4-wait-n`, `no-gnu-sed-in-place` and
# `no-gnu-xargs-r` already deny the usual shortcuts. CI runs ubuntu and is
# structurally blind to all of them, so an associative array would pass here and
# fail on a contributor's machine. `declare -A` is bash 4.
#
# So the index is a newline-delimited string and the lookup is parameter
# expansion, which runs IN PROCESS: no `jq`, no `grep`, no fork per lookup. Each
# record is `\n<key>\t<value>` and both delimiters are structural — an issue key
# carries neither, so no record can be confused with part of another.
#
# The verdicts are unchanged, and that is the whole obligation: this alters how a
# lookup is resolved and no predicate, rule id or exit code. The suite's existing
# cases ARE the parity assertion, which is why none of them moved.
status_index=$(jq -r '.[] | "\(.id)\t\(.status)"' <<<"$issues")
status_index=$'\n'"$status_index"$'\n'
id_index=$'\n'"$ids"$'\n'

# Membership: is this key one of the piped rows?
in_set() { [[ "$id_index" == *$'\n'"$1"$'\n'* ]]; }

# The status the board gave this row, or the empty string when the set does not
# carry it. The empty answer is load-bearing and has two readers — the
# status-claim scan reports `status-claim-unjudgeable` on it, and the frontier
# loop guards with `in_set` before trusting it (CLOUD-678).
status_of() {
	local rest=${status_index#*$'\n'"$1"$'\t'}
	[[ "$rest" != "$status_index" ]] || return 0
	printf '%s' "${rest%%$'\n'*}"
}

# The board's TYPE for this row's column, or the empty string when the set does not
# carry it. CLOUD-477 needs this because the frontier resolved a blocker by column
# NAME, and a name match cannot see a terminal column it was not told about.
statustype_index=$(jq -r '.[] | "\(.id)\t\(.statusType // "")"' <<<"$issues")
statustype_index=$'\n'"$statustype_index"$'\n'
statustype_of() {
	local rest=${statustype_index#*$'\n'"$1"$'\t'}
	[[ "$rest" != "$statustype_index" ]] || return 0
	printf '%s' "${rest%%$'\n'*}"
}

# WHAT §6 DECLARES FOR THIS ROW, or the empty string when the row's body carries
# no §6 clause at all (CLOUD-735).
#
# The value comes from `ready-lint`'s emission, never from a second parse here.
# That grammar is subtle on purpose — the whole-code-span anchoring is CLOUD-290's,
# discovered by experiment after a prefix match read `ci` out of a filename — so a
# copy of it in this file is a copy that drifts silently. This is CLOUD-806's
# pattern: the producer emits the structure it already built, and the consumer
# reads it.
#
# BUILT LAZILY, ONE ROW AT A TIME, and only for In Review rows. `ready-lint` is a
# process per call, and the Todo loop below already pays that per row; paying it
# again for every row in the set — most of which are neither — would make a sweep
# quadratic in the wrong direction for a fact almost nobody needs.
#
# A row whose lint cannot run reads as "did not say", which leaves
# `in-review-no-pr` deciding exactly as it did before this existed. Could-not-look
# must not manufacture an exemption.
bump_of() { # bump_of <id>
	local payload
	payload=$(jq -c --arg id "$1" '.[] | select(.id == $id)' <<<"$issues" 2>/dev/null) || return 0
	[[ -n "$payload" ]] || return 0
	# stdout only: the emission is a stdout line and the verdict is on stderr, so a
	# refused row still reports what its §6 said. `|| true` because a row that fails
	# the lint exits non-zero and its declaration is still the honest answer.
	printf '%s' "$payload" | "$lint" 2>/dev/null | awk '$1 == "bump" { print $2; exit }' || true
}

# IS THIS BLOCKER SETTLED? (CLOUD-477.) The frontier loop asked `case "$(status_of
# …)" in Done | "In Review")`, so anything not literally one of those two names fell
# into the catch-all and blocked. Two terminal columns land there, and both mean
# "this work will never be done, and that is settled" — so the dependent was
# excluded from the frontier PERMANENTLY, with no path back but a human noticing.
# Worse than a wrong answer, because the exclusion prints as `excluded (blocked-by
# …)` and reads exactly like a legitimate block.
#
# MEASURED, AND THE ROW'S OWN §1 IS WRONG ABOUT IT. That clause says the payload
# carries "a canceled type covering both `Canceled` and `Duplicate`". It does not:
# `Canceled` is `canceled` and `Duplicate` is `duplicate`, two distinct values
# (2026-08-23, over the live board). Keying on one of them would have fixed half the
# defect and left `Duplicate` starving — including CLOUD-335, the example the row
# itself cites. Both are named here for that reason.
#
# `In Review` STAYS NAME-BASED, and that is not an oversight: its type is `started`,
# the same value `In Progress` carries, so a type-only rule would starve every row
# behind landed-but-unreleased work. Confirmed on the live board.
#
# One test per line and no `|` in any of them, so each arm is separately mutable —
# `mutant.sh` reads a declaration with `IFS='|'`, and a pattern carrying its own pipe
# shifts every field after it.
blocker_resolved() { # blocker_resolved <id>
	local t
	t=$(statustype_of "$1")
	[[ "$t" = completed ]] && return 0
	[[ "$t" = canceled ]] && return 0
	[[ "$t" = duplicate ]] && return 0
	[[ "$(status_of "$1")" = "In Review" ]] && return 0
	return 1
}

# Does this row carry a milestone at all — `set`, `null`, or the empty string when
# the set does not carry the row? CLOUD-599's clause needs the PARENT's answer while
# the loop below is on the child, and presence is the whole question (see the clause
# for why identity is not). Same shape and same bash-3.2 reason as `status_of`:
# parameter expansion in process, never `declare -A`.
milestone_col_index=$(jq -r '.[] | "\(.id)\t\(if (.projectMilestone // null) == null then "null" else "set" end)"' <<<"$issues")
milestone_col_index=$'\n'"$milestone_col_index"$'\n'
milestone_col_of() {
	local rest=${milestone_col_index#*$'\n'"$1"$'\t'}
	[[ "$rest" != "$milestone_col_index" ]] || return 0
	printf '%s' "${rest%%$'\n'*}"
}

# --- the milestone claim's anti-vacuity arm (CLOUD-695) -----------------------
#
# `todo-unmilestoned` below cannot be decided per issue, and that is a property of
# the tracker rather than a softening: Linear OMITS `projectMilestone` entirely
# when it is null, so on one payload "this issue has no milestone" and "the caller
# projected the field away" are the same bytes. Deciding from that alone is
# CLOUD-679's defect — a violation reported where the gate cannot look.
#
# The discriminator is the SET, which is how `unjudgeable-blockedby` and
# `unjudgeable-description` already resolve the same ambiguity in this file: if no
# issue anywhere in the piped set carries the key, the caller projected it away.
# If any issue carries it, the connector was emitting the field, so its absence
# elsewhere is the tracker saying "none".
#
# Scoped to the Todo ids, because a set holding no Todo issue has no milestone
# claim to judge and reporting one would fire on the ordinary shape.
#
# THE HONEST LIMIT, stated rather than left to be met: a set in which EVERY issue
# is genuinely unmilestoned reads as projected-away and reports unjudgeable. That
# is the conservative direction — could-not-look, never a wrong answer — and the
# message names the fix, which a caller can take in one re-fetch.
# THE SET IT SCOPES TO WIDENS WITH THE CLAUSE (CLOUD-771). It was the Todo ids;
# it is now every STARTED row, because a set holding only In Progress and In Review
# rows would otherwise report unjudgeable where it should report violations — the
# arm going stale in the quiet direction the moment the clause it guards grew.
milestone_judgeable=1
started_ids=$(jq -r '[.[] | select(.status == "Todo" or .status == "In Progress" or .status == "In Review") | .id] | join(" ")' <<<"$issues")
if [[ -n "$started_ids" ]] && ! jq -e 'any(.[]; has("projectMilestone"))' <<<"$issues" >/dev/null 2>&1; then
	milestone_judgeable=0
	unjudged "graph" "unjudgeable-milestone ($(tr ' ' '\n' <<<"$started_ids" | by_num | tr '\n' ' ' | sed 's/ $//'))"
fi

# --- the three board predicates -----------------------------------------------
while IFS=$'\t' read -r id status assignee prs milestone parent; do
	if [[ "$status" = "In Progress" ]] && [[ "$assignee" = "null" ]]; then
		report "$id" "in-progress-unassigned"
	fi
	# A ROW THAT DECLARES IT LANDS NO COMMIT IS EXEMPT (CLOUD-735), and a row that
	# declares that AND carries a PR is refused for the contradiction.
	#
	# `in-review-no-pr` keys on an artifact. A dispatch record's deliverable is a
	# `create_session` per bundle and a board state, so it opens no PR — and
	# `done-check` refuses a Done no tag reaches, so it lands no commit either.
	# Both gates out of In Progress therefore key on artifacts the row can never
	# produce, and three records sat In Progress with their campaigns finished
	# (CLOUD-607, 632, 703), indistinguishable from work someone abandoned.
	#
	# THE DECLARATION IS ALREADY IN THE BODY AND ALREADY PARSED. §6 answers "commit
	# / bump", `ready-lint` accepts `none` as an explicit answer — a Linear-only
	# change lands no commit and demanding a type there would force a lie — and
	# CLOUD-926's own block uses exactly that spelling. So this invents no
	# vocabulary and adds no fourth authority: it reads the fact `ready-lint`
	# emits, which is CLOUD-806's shape.
	#
	# THE ANTI-CHEAT IS THE HALF THAT MATTERS. Exempting a self-declaration would
	# make `none` the cheapest way past the gate for any row at all, which is the
	# roster cheat CLOUD-607 names — attaching an unrelated PR to satisfy this
	# predicate. A row cannot have it both ways: if it declares no commit and a PR
	# is nonetheless attached, the declaration is false and the row is refused.
	if [[ "$status" = "In Review" ]]; then
		declares_none=0
		if [[ "$(bump_of "$id")" = none ]]; then
			declares_none=1
		fi
		if [[ "$prs" = 0 ]] && [[ "$declares_none" = 0 ]]; then
			report "$id" "in-review-no-pr"
		fi
		if [[ "$prs" != 0 ]] && [[ "$declares_none" = 1 ]]; then
			report "$id" "declares-no-commit-with-pr"
		fi
	fi
	# CLOUD-695. Todo is the ready queue, so sitting in it is a claim that this is
	# pullable work — and pullable work has to say which phase it advances. Nothing
	# asked, for ~340 issues: measured 2026-08-19, 174 open issues carried no
	# milestone, and the split was provenance rather than age. Issues authored as a
	# plan carried one; issues DISCOVERED during work did not, because filing is one
	# `save_issue` and no gate stood on that path.
	#
	# The seam is Todo and not filing, deliberately. A finding reaching the board at
	# all is what CLOUD-505 bought, and demanding a milestone at file time would tax
	# triage at the moment the issue is least understood. Todo already costs a Ready
	# block (`todo-not-ready`), on exactly this argument.
	#
	# A REPORT, not a frontier note, for `todo-not-ready`'s reason: the column is
	# signalling falsely rather than merely excluding itself from the queue.
	#
	# CLOUD-599's `child-unmilestoned` is the other quantifier over the same field —
	# a child inherits its parent's phase — and the two compose rather than overlap:
	# that one ranges over PARENTED issues, and most of the 174 have no parent at
	# all, so every one of them passes it.
	# CLOUD-771 WIDENED THIS FROM Todo TO EVERY STARTED COLUMN, and the reason is
	# that the seam was placed where the claim is weakest. Todo is the column an
	# agent is instructed to LEAVE as fast as possible — AGENTS.md says claim before
	# writing code — so the ordinary compliant workflow was itself the escape.
	# Measured: CLOUD-769 was filed unphased, sat in the gated column for 138
	# seconds, and left it unphased with no rule broken and no gate fired. Over the
	# live board, 20 unparented rows outside Todo carried no milestone: 4 In
	# Progress, 16 In Review, against 0 in Todo, which had been swept that day.
	#
	# In Progress and In Review are STRONGER claims than "pullable", not weaker: one
	# says work is being done and the other that it landed. Backlog stays out
	# deliberately — that is what CLOUD-505 bought, and demanding a phase at file
	# time taxes triage when the issue is least understood. Done, Canceled and
	# Duplicate stay out because a closed row's phase changes nothing.
	#
	# A PARENTED ROW IS SKIPPED, so CLOUD-599's `child-unmilestoned` owns it and no
	# row is reported twice. That clause ranges over `(child, parent)` pairs and
	# inherits the parent's phase; this one ranges over rows with no parent to
	# inherit from, which is the overwhelming majority.
	if [[ "$milestone_judgeable" = 1 ]] && [[ "$parent" = "null" ]] &&
		[[ "$status" = "Todo" || "$status" = "In Progress" || "$status" = "In Review" ]] &&
		[[ "$milestone" = "null" ]]; then
		# THE RULE ID CARRIES THE COLUMN NOW, rather than naming one. `todo-unmilestoned`
		# was accurate while the clause was Todo-only and would be a lie in either
		# direction once it is not — a reader seeing it on an In Review row would
		# mistrust the gate, and a second id per column would be two names for one
		# predicate. `released`'s `refusal_for` reads the first `[a-z-]+` token, so
		# `unmilestoned` still resolves for it.
		report "$id" "unmilestoned ($status)"
	fi

	# --- CLOUD-599: a child inherits its parent's phase ------------------------
	#
	# "Is Phase 3 done" had two answers over two different sets and nothing
	# reconciled them: milestone membership is what the progress bar counts, the
	# epic tree is what the epics promise ("they carry no work of their own and
	# close when their children close"). Measured over 39 children of the three
	# Phase 3 epics, the sets disagreed in BOTH directions — and the milestone
	# could therefore read 100% with four issues its own epics parent still open,
	# which is a completion signal that means nothing.
	#
	# THE DECISION IS THE ROW'S, taken 2026-08-17 and not re-litigated here: the
	# epic tree is authoritative for phase membership. A child of a milestoned
	# parent belongs to that parent's phase unless deliberately re-phased, and a
	# re-phase must be DECLARED by carrying the other milestone rather than by
	# carrying none. That is what makes the epics' promise meaningful.
	#
	# FOUR ARMS, and only one of them refuses:
	#
	#   parent not in the piped set  -> unjudgeable. A closure that does not carry
	#                                   the parent cannot answer, and guessing from
	#                                   its absence is CLOUD-678's defect exactly —
	#                                   which is why this reuses `in_set` rather
	#                                   than minting a second reading of it.
	#   parent carries no milestone  -> pass. No pair can diverge, and reporting it
	#                                   would fire on the ordinary shape.
	#   child carries a DIFFERENT one -> pass. The declared re-phase, and the
	#                                   difference between a gate and a nuisance.
	#                                   Four live rows depend on this arm.
	#   child carries NONE           -> REFUSED. The silent case, all eight live
	#                                   instances, and the only one where the
	#                                   divergence is absent from the data instead
	#                                   of recorded in it.
	#
	# THE REFUSAL NEEDS PRESENCE, NEVER IDENTITY, and getting that wrong cost a
	# regression worth recording. The first cut of this clause projected the
	# milestone's ID so it could compare the child's against the parent's — on the
	# reasoning that telling a declared re-phase from a silent gap needs identity.
	# It does not: BOTH the same-milestone and different-milestone arms PASS, so the
	# only distinction the refusal draws is "the child carries one" against "the
	# child carries none". Identity would only ever be used to decide not to refuse.
	#
	# The cost of the wrong cut was measured rather than argued: making `.id`
	# load-bearing read `tests/board-sweep.bats`'s `projectMilestone: {name: "m"}` —
	# a fixture with no `id` — as ABSENT, so two of that suite's cases went red on a
	# clean tree and `mutant` reported them `case-already-red`. Collapsing "present
	# but idless" into "absent" is the same could-not-look conflation this file
	# fixes everywhere else, and the boolean projection never had it.
	#
	# Pointer-only: the child, the rule, and the parent. §5 suggests naming the
	# milestone too; a name is a wide free-text field that decides nothing here, and
	# `released`'s `refusal_for` reads the first `[a-z-]+` token either way.
	if [[ "$milestone_judgeable" = 1 ]] && [[ "$parent" != "null" ]]; then
		if ! in_set "$parent"; then
			unjudged "$id" "child-milestone-unjudgeable (parent $parent not in the set)"
		elif [[ "$(milestone_col_of "$parent")" = "set" ]] && [[ "$milestone" = "null" ]]; then
			report "$id" "child-unmilestoned (parent $parent)"
		fi
	fi
	# EVERY FIELD CARRIES A PLACEHOLDER, never the empty string. Tab is whitespace to
	# `read`, so consecutive tabs COLLAPSE and one empty column shifts every field after
	# it left — the defect measured on `duplicate-close-check` this same day, where a row
	# with no timestamp read its own duplicate target as the timestamp and then passed.
	# `parentId` is the field CLOUD-771 added and the one most often absent.
done < <(jq -r '.[] | [.id, .status, (.assigneeId // "null"), ([.attachments[]? | select(.url | test("github.com/.*/pull/"))] | length), (if (.projectMilestone // null) == null then "null" else "set" end), (.parentId // "null")] | @tsv' <<<"$issues" | by_num)

# --- graph coherence ----------------------------------------------------------
#
# ANTI-VACUITY FIRST (CLOUD-251). `blockedBy[]?` yields nothing for a payload
# that never carried the key, so a caller who projected the relations away got
# zero edges, an unconditional "board coherent", and exit 0 — the acyclicity and
# non-dangling claims asserted over a set whose edges it could not see. An
# explicit `blockedBy: []` is DATA and is judged; only an absent key is
# unjudgeable, which is the same distinction `released` draws on `attachments`.
#
# Keyed to the `graph` pseudo-id the cycle report already uses, and deliberately
# NOT one line per issue: `released`'s `refusal_for` greps this stderr for
# `^<id> <rule>` and turns any hit into a REFUSED verdict on that issue. A
# per-id line would convert every In Review issue in a relations-free sweep into
# a refusal — the property is of the piped SET, exactly like `dangling-blocker`.
no_edge_key=$(jq -r '[.[] | select((try (.relations | has("blockedBy")) catch false) | not) | .id] | join(" ")' <<<"$issues")
if [[ -n "$no_edge_key" ]]; then
	unjudged "graph" "unjudgeable-blockedby ($(tr ' ' '\n' <<<"$no_edge_key" | by_num | tr '\n' ' ' | sed 's/ $//'))"
fi

edges=$(jq -r '.[] | .id as $id | .relations.blockedBy[]?.id | "\($id) \(.)"' <<<"$issues" | by_num)

# ADJACENCY, INDEXED (CLOUD-634). The frontier loop asked `grep -E "^$id "` over
# the whole edge list once per id — O(V·E) with a process per node. This walks the
# list once, in process, and emits the same `<from> <to>` lines in the same order,
# so the loop that reads it is untouched. `while read` over a here-string rather
# than parameter expansion here because the answer is a SET of lines, not one
# value, and the caller wants them one at a time.
edges_from() { # edges_from <id> -> the edge lines whose FROM is <id>
	local want=$1 line
	while IFS= read -r line; do
		[[ "$line" == "$want "* ]] || continue
		printf '%s\n' "$line"
	done <<<"$edges"
}

# `dangling-blocker` IS AN UNJUDGED ARM, NOT A VIOLATION (CLOUD-678), and it is
# set-keyed like the two arms above rather than keyed to the dependent.
#
# THE OPEN CALL THIS ROW WAS ASKED TO DECIDE, with the rejected option recorded.
# Rejected: keep it exit 1 on the argument that it is the anti-vacuity guard and
# weakening it lets a caller project edges away. That argument belongs to
# `unjudgeable-blockedby` above, which fires when the KEY is absent — a caller who
# projects the relations away is caught there, and this arm never was that guard.
#
# What decided it is a measurement rather than the balance of arguments. Linear
# does NOT drop `blockedBy` when the blocker completes (CLOUD-661 has been Done
# since 2026-08-18T23:01:59Z and both dependents still carry the edge), so an
# active-only closure — the closure the workflow actually prescribes — carries an
# edge to a Done ancestor for every landed blocker. Measured on `b2f8992`: piping
# `{672, 674}` produced `dangling-blocker` twice over a board that was correct. A
# violation that fires on correct input trains readers to ignore it.
#
# And it makes the two arms agree, which is the part that could not be left: one
# fact — a blocker outside the piped closure — was exit 1 here and about to become
# exit 2 in the frontier loop below. `released`'s `refusal_for` already carries a
# hand-written `grep -vx 'dangling-blocker'` to undo the id-keying; set-keying it
# makes that filter structurally unnecessary rather than merely unused.
out_of_closure=""
while read -r from to; do
	[[ -n "$from" ]] || continue
	in_set "$to" || out_of_closure="$out_of_closure $to"
done <<<"$edges"
if [[ -n "$out_of_closure" ]]; then
	unjudged "graph" "dangling-blocker ($(tr ' ' '\n' <<<"${out_of_closure# }" | sort -u | by_num | tr '\n' ' ' | sed 's/ $//'))"
fi

if [[ -n "$edges" ]] && ! tsort <<<"$edges" >/dev/null 2>&1; then
	cycle=$(tsort <<<"$edges" 2>&1 >/dev/null | grep -oE 'CLOUD-[0-9]+' | by_num | sort -u | tr '\n' ' ' || true)
	report "graph" "blockedby-cycle (${cycle% })"
fi

# --- status claims: the board is the one authority for a column (CLOUD-234) ---
#
# A refinement sweep groomed seven issues while other sessions were landing work,
# and every block carried the same defect: prose restating a column the board
# owns, already stale when saved. CLOUD-8's child inventory said "CLOUD-87 — In
# Progress (PR #157)" two seconds AFTER CLOUD-87 completed and its PR merged. All
# seven passed ready-lint at exit 0, and an epic's child inventory is read as the
# frontier, so a stale column sends an implementer at finished work.
#
# It is the §8 relation claim in a different clause: prose asserting something the
# board decides, with nothing checking it. It cannot live in ready-lint, which is
# a pure function of ONE issue and structurally cannot know another's status. This
# script already takes the set and already resolves ids across it.
#
# THE VOCABULARY COMES FROM THE PAYLOADS, never a second copy of the board's
# status list. The consequence is real and stated rather than worked around: a
# column no piped issue occupies is not in the vocabulary, so a claim naming it is
# not recognised — the same way the frontier is already relative to the closure.
# shellcheck disable=SC2016  # the $ is a regex metacharacter being escaped, not an expansion
columns=$(jq -r '[.[].status] | unique | .[]' <<<"$issues" | sed 's/[][\.*^$(){}?+|/]/\\&/g' | paste -sd'|' -)

# A CAPITALIZED SPAN — one or more capitalized words (CLOUD-838). This is what
# stands in for a column the alphabet above cannot spell, and it is multi-word
# because the columns it has to name are: reporting `In` for a claim of
# `In Review` would point at nothing a reader can act on.
CAPSPAN='[A-Z][A-Za-z]*([[:space:]]+[A-Z][A-Za-z]*)*'

# ANTI-VACUITY, the conjunct CLOUD-251 applied to `blockedBy`: a set whose
# descriptions were projected away has nothing to scan, and "found no claims"
# would read as "made no false claims". Set-keyed for the same reason as
# unjudgeable-blockedby — it is a property of the piped set, not of an issue.
no_desc=$(jq -r '[.[] | select((.description | type) != "string") | .id] | join(" ")' <<<"$issues")
if [[ -n "$no_desc" ]]; then
	unjudged "graph" "unjudgeable-description ($(tr ' ' '\n' <<<"$no_desc" | by_num | tr '\n' ' ' | sed 's/ $//'))"
fi

# CLAIMS, NOT MENTIONS — the precision discipline ready-lint's §8 span already
# solves, in the same order:
#
#   1. strip Linear's <issue …> mention markup, so the stored and rendered forms
#      are one case (ready-lint does this before reading §8 claims);
#   2. neutralise backticked and quoted spans, the treatment deferral-check gives
#      a paragraph that NAMES a phrase rather than USING it. Load-bearing, not
#      defensive: CLOUD-234's own body quotes the measured defect verbatim, so
#      without this the gate fails the issue that ships it;
#   3. match an id-first span whose CONNECTIVE is allowlisted, not blocklisted.
#
# The connective is where this was measured and rewritten. The first version
# bounded the span by length and dropped `was`/`were`/`had been` as history —
# and over this repo's own prose it fired three times, all wrong: "CLOUD-49 went
# In Progress", "CLOUD-192 still read In Progress", "CLOUD-468's question), and a
# Done". Every one is narration, and no blocklist of past-tense verbs ends: the
# next one is `went`, `sat`, `showed`, `landed`. So the rule is inverted. Between
# the id and the column may stand ONLY punctuation, markdown emphasis and
# whitespace — optionally one present-tense connective, `is` / `is now` / `now`.
# A claim is a gloss (`CLOUD-87 — **In Progress**`, `| CLOUD-3 | Done |`) or an
# assertion (`CLOUD-2 is In Progress`); everything with a verb in it is prose
# ABOUT an issue, which is what an epic is made of. Re-measured over the same
# corpus: zero hits, with all four claim shapes still caught.
#
# Case-SENSITIVE, because the columns are proper nouns the payload spells exactly
# and `-i` would read a `TODO` comment as a column. Id-first only: every measured
# instance is `CLOUD-87 — **In Progress**`, and the reverse direction doubles the
# false-positive surface with no measured shape behind it. Backslash is out of the
# filler class, so a claim cannot bridge the `\n` @tsv leaves between two lines —
# which is also what keeps the unbounded `*` from running away.
#
# The id and the column are read as the LAST of each in the span: grep -o returns
# non-overlapping matches, so the id nearest the column word is the one the column
# is about.
BACKTICK='`'
while IFS=$'\t' read -r claimer desc; do
	[[ -n "$claimer" ]] || continue
	prose=$(sed -E 's|</?issue[^>]*>||g' <<<"$desc")
	prose=$(sed -E "s/${BACKTICK}[^${BACKTICK}]*${BACKTICK}/CODESPAN/g; s/\"[^\"]*\"/QUOTED/g" <<<"$prose")
	while IFS= read -r claim; do
		[[ -n "$claim" ]] || continue
		cited=$(grep -oE 'CLOUD-[0-9]+' <<<"$claim" | tail -n1)
		claimed=$(grep -oE "($columns)" <<<"$claim" | tail -n1)
		actual=$(status_of "$cited")
		if [[ -z "$actual" ]]; then
			# An id outside the piped set is reported, never guessed — and keyed to
			# the set, since which closure was piped is the caller's choice.
			unjudged "graph" "status-claim-unjudgeable ($claimer claims $cited, not in the piped set)"
		elif [[ "$actual" != "$claimed" ]]; then
			# Pointer-only: the two column names and the ids, never the prose.
			report "$claimer" "status-claim-disagrees ($cited claimed $claimed, board says $actual)"
		fi
	done < <(grep -oE "CLOUD-[0-9]+[^[:alnum:]\\\\]*((is|is now|now)[^[:alnum:]\\\\]*)?($columns)" <<<"$prose" || true)

	# --- the alphabet's own anti-vacuity arm (CLOUD-838) ---------------------
	#
	# The scan above can only judge a claim whose column word is in `$columns`,
	# and `$columns` is the piped set's OCCUPIED statuses. So a claim naming any
	# other column is not refuted, not reported unjudgeable — the regex simply
	# never matches it, and the row passes silently. That inverts the predicate:
	# the claims most likely to be stale are claims that a row LEFT a column,
	# and a row that left one is precisely the row whose old column nothing in
	# the set need occupy any more. The gate is weakest where it is most needed.
	#
	# MEASURED 2026-08-21 on CLOUD-743, which carries a claim and its own
	# correction ~40 lines apart: `CLOUD-740 is now Canceled` (false) and
	# `CLOUD-740 is Todo, not Canceled` (true). Over a 19-row closure the gate
	# matched the CORRECTION — `Todo` is in the vocabulary because piped rows sit
	# in it — compared it against the board, and passed. The false claim beside it
	# was invisible, because no piped row is `Canceled`.
	#
	# So this is the arm `unjudgeable-milestone` already has one level up
	# (CLOUD-695), applied one level down: not to a field missing from the input,
	# but to a word missing from the input's alphabet. `could not look` gets its
	# own channel instead of collapsing into `nothing to see` — CLOUD-251's split.
	#
	# THE CONNECTIVE IS REQUIRED HERE AND OPTIONAL ABOVE, and the asymmetry is the
	# whole bound on false triggers. Above, `$columns` is what says a span is a
	# column claim at all, so a gloss (`CLOUD-87 — **In Progress**`) is safe to
	# match. Here there is no vocabulary to lean on: any capitalized word would
	# qualify, so `| CLOUD-3 | Batten |` and `| CLOUD-3 | Done |` are the same
	# bytes to a gate forbidden a second copy of the status list (§1). The
	# present-tense connective is the only thing left that distinguishes an
	# ASSERTION from a mention, so it is mandatory — which leaves the gloss form
	# of an unspellable column uncovered, and that is a stated bound rather than
	# an oversight: closing it needs an authority this gate must not have.
	#
	# Ordinary prose survives it for the same reason it survives the scan above:
	# `CLOUD-129 is the durable artifact` has a connective and no capital.
	while IFS= read -r claim; do
		[[ -n "$claim" ]] || continue
		token=$(grep -oE "${CAPSPAN}\$" <<<"$claim") || token=""
		[[ -n "$token" ]] || continue
		# In the alphabet: the scan above already judged it, and reporting here
		# too would double-report one claim under two rule ids.
		if grep -qxE "($columns)" <<<"$token"; then
			continue
		fi
		cited=$(grep -oE 'CLOUD-[0-9]+' <<<"$claim" | tail -n1)
		# Keyed to the SET, like `status-claim-unjudgeable`: which closure was
		# piped is the caller's choice, not this issue's dishonesty. Pointer-only
		# per non-negotiable rule 4 — two ids and one token, never the prose. The
		# refusal names its own remedy, which is one re-fetch.
		unjudged "graph" "status-claim-unscannable ($claimer claims $cited is $token, which no piped issue occupies — pipe one that does)"
	done < <(grep -oE "CLOUD-[0-9]+[^[:alnum:]\\\\]*(is|is now|now)[^[:alnum:]\\\\]*${CAPSPAN}" <<<"$prose" || true)
done < <(jq -r '.[] | select((.description | type) == "string") | [.id, .description] | @tsv' <<<"$issues" | by_num)

# --- the frontier and WIP, on stdout ------------------------------------------
#
# Frontier membership composes the one definition of Ready rather than copying
# it: a Todo issue is on the frontier iff its own payload passes ready-lint and
# every blocker in the piped set is resolved. Resolved means Done or In Review —
# landed code is on main, so a dependent can build on it.
#
# EVERY EXCLUSION IS ATTRIBUTED (CLOUD-251). This loop used to end an exclusion
# with `|| continue`, which threw away the one thing that made it readable:
# ready-lint already separates exit 1 ("this block is wrong", with pointer-only
# rule ids) from exit 2 ("stdin is not a payload with a .description field"), and
# both arrived here as an identical silent absence. Its rule ids are FORWARDED,
# never re-derived — the one definition of Ready keeps its own vocabulary.
#
# AND THE THREE ARMS END IN THREE DIFFERENT PLACES, which is the whole of
# CLOUD-375's change: ready-lint's exit 1 is `todo-not-ready`, a violation,
# because a Todo issue whose block fails is the ready queue lying; its exit 2
# stays exit 2, because "the caller piped a shape I cannot read" is not a failing
# issue — the same split `released` makes for a payload assembled without
# `attachments`, and collapsing it into the violation would send a caller to fix a
# board over a question that was never asked. An unlanded blocker stays a note at
# exit 0 below: that is scheduling, and the issue is not claiming otherwise.
#
# ready-lint's `::error::` summary is still dropped on every arm. At exit 2 it
# would annotate a failure at a code that denies one; at exit 1 it is a second
# summary for one verdict, and this gate prints its own count at the bottom.
frontier=()
while read -r id; do
	[[ -n "$id" ]] || continue
	[[ "$(status_of "$id")" = "Todo" ]] || continue
	lint_rc=0
	lint_err=$(jq -c --arg id "$id" '.[] | select(.id == $id)' <<<"$issues" | "$lint" 2>&1 >/dev/null) || lint_rc=$?
	case "$lint_rc" in
	0) ;;
	1)
		report "$id" "todo-not-ready"
		grep -v '^::error::' <<<"$lint_err" >&2 || true
		continue
		;;
	*)
		unjudged "$id" "excluded (unjudgeable-ready-block)"
		continue
		;;
	esac
	# THREE ARMS, NOT TWO (CLOUD-678). `status_of` is a `jq` select over the piped
	# payloads, so for an id that is not in the set it returns the empty string —
	# which fell into this case's catch-all and converted "I was not given this
	# blocker" into "this blocker has not completed". Measured on `b2f8992`: two
	# Todo rows whose only blocker had completed the night before were withheld
	# from the frontier, over a closure that prescribes excluding Done rows.
	#
	# The discriminator is `in_set`, the file's own predicate, rather than a new
	# sentinel from `status_of` — the status-claim scan above already resolves the
	# same ambiguity that way (`status-claim-unjudgeable`), and a sentinel would
	# have to be taught to every reader of that function to answer one of them.
	#
	# So an out-of-closure blocker is UNJUDGED and never a note: a silent frontier
	# omission is what made this invisible, because `excluded (blocked-by …)` reads
	# identically to a legitimate block and an empty frontier reads as "nothing is
	# ready" — which CLOUD-607's acceptance treats as success.
	ok=1
	blocking=""
	unknown=""
	retired=""
	while read -r _ to; do
		[[ -n "$to" ]] || continue
		if ! in_set "$to"; then
			ok=0
			unknown="$unknown $to"
			continue
		fi
		if ! blocker_resolved "$to"; then
			ok=0
			blocking="$blocking $to"
			continue
		fi
		# A blocker that resolved because it was RETIRED rather than completed is
		# collected, not silently swallowed — see the note below.
		case "$(statustype_of "$to")" in
		canceled | duplicate) retired="$retired $to" ;;
		esac
	done < <(edges_from "$id")
	if [[ "$ok" = 1 ]]; then
		frontier+=("$id")
		# CLOUD-477's SECOND DECISION, taken rather than assumed. Resolving a retired
		# blocker is right for the frontier and is not obviously right for the WORK: an
		# issue whose blocker was cancelled may have had its premise removed with it. So
		# the row is schedulable AND the reason is on the record. A `note`, so the exit
		# code is unmoved — this is information about a coherent board, not a finding.
		[[ -z "$retired" ]] || note "$id" "frontier-over-retired-blocker${retired}"
	elif [[ -n "$unknown" ]]; then
		# Keyed to the ISSUE rather than to `graph`, unlike the arm above: this one
		# is why THIS row is off the frontier, so a reader needs the dependent's id
		# to act on it. The blockers it could not resolve are named beside it.
		# The id-keying that would be wrong above is safe here for a structural
		# reason rather than by luck: this loop judges only `Todo` rows, and
		# `released`'s `refusal_for` asks only about `In Review` ones, so no line
		# from here can reach it. `excluded (unjudgeable-ready-block)` above is
		# already id-keyed on the same argument.
		unjudged "$id" "excluded (unjudgeable-blocker${unknown}${blocking})"
	else
		note "$id" "excluded (blocked-by${blocking})"
	fi
done <<<"$ids"

echo "wip $(jq -r '[.[] | select(.status == "In Progress")] | length' <<<"$issues")"
for id in "${frontier[@]:-}"; do
	[[ -n "$id" ]] && echo "frontier $id"
done

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: graph-check: $violations violation(s) — the board is signalling falsely" >&2
fi
# EXIT 2 OUTRANKS EXIT 1 (CLOUD-251), and both report sets print before either
# exit so one never hides the other. A verdict over a set this could only partly
# read is not a verdict: the caller's next action is a re-fetch, after which more
# violations may appear, so answering "your board is wrong" first would send them
# to fix a board over a question that was never fully asked. `1` stays reserved
# for a board that is demonstrably signalling falsely.
if [[ "$unjudgeable" -ne 0 ]]; then
	echo "::error:: graph-check: $unjudgeable payload(s) could not be judged — re-fetch with get_issue(includeRelations: true)" >&2
	exit 2
fi
[[ "$violations" -eq 0 ]] || exit 1

# --- the receipt board-move-guard demands (CLOUD-512) -------------------------
#
# This gate already decides `in-review-no-pr` correctly, and CLOUD-309 bound it to
# the release sweep. Nothing bound the TRANSITION, so a bulk sweep could label
# unlanded work as landed and the gate only found out if somebody thought to run
# it — measured on CLOUD-480, wrong for 4.5 hours.
#
# The trigger is a receipt rather than a second predicate: a hook has no tracker
# credential (this file's own agents-fetch-gates-decide note), so the guard cannot
# look an issue up. It asks only whether the closure was adjudicated, and this is
# where that becomes a fact on the filesystem.
#
# MINTED ONLY HERE, ON THE SUCCESS PATH. A board carrying violations must not
# authorise a move — that is the whole point — so this sits after both exits.
#
# ONE FILE PER ID, because the receipt has to be keyed to the SET and a
# per-subject file IS that keying. A bare "graph-check ran" receipt is satisfied
# by judging one clean issue and then sweeping fifteen, which is exactly the sweep
# that produced CLOUD-512.
#
# THE SHAPE CHANGED WITH CLOUD-312 ROW 3 AND THE PREDICATE DID NOT. It was one
# `board-move` file carrying `<epoch> <id> <id> …` per run, read by a guard that
# grepped for the id and took the newest stamp it found. The engine's `named`
# receipt key is one file per subject (`<check>.<subject>`), so the set is now
# expressed as the set of files rather than as words inside a line — the same
# question, asked of the filesystem instead of of a regex, and the `\b$key\b`
# anchoring that kept CLOUD-48 from reading as CLOUD-480 is structural now.
#
# TRUNCATED, not appended, and that is what makes the age readable: the engine
# bounds recency by the file's MTIME, so the freshest adjudication of a subject has
# to overwrite the stalest rather than sit behind it in the same file. The epoch
# stays in the body for a human reading the store.
#
# THE ID IS SHAPE-CHECKED BEFORE IT BECOMES A PATH COMPONENT. `named_validity`
# refuses a subject carrying a separator on the read side; this is that hazard on
# the write side, and a board payload is data from somewhere else. A value that is
# not an issue key mints nothing, which is the same posture the guard took: it
# cannot be a subject anything asks about.
#
# FAIL-SOFT. A receipt that cannot be written must not turn a coherent board into
# a failing one — this gate's verdict is about the board, never about the store.
if git_dir=$(git rev-parse --git-dir 2>/dev/null) && [[ -n "$git_dir" ]] &&
	mkdir -p "$git_dir/batten-receipts" 2>/dev/null; then
	receipt_stamp=$(date -u +%s)
	while read -r receipt_id; do
		[[ -n "$receipt_id" ]] || continue
		case "$receipt_id" in
		*[!A-Za-z0-9-]*) continue ;;
		[A-Z]*-[0-9]*) ;;
		*) continue ;;
		esac
		printf '%s %s\n' "$receipt_stamp" "$receipt_id" \
			>"$git_dir/batten-receipts/board-move.$receipt_id" 2>/dev/null || true
	done <<<"$ids"
fi

echo "graph-check: board coherent ($(wc -l <<<"$ids" | tr -d ' ') issues)"
