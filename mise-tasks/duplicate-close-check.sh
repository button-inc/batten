#!/usr/bin/env bash
#MISE description="Gate: a duplicate close decided in the same operation as its target's close (reads get_issue payloads on stdin) — CLOUD-829"
#
# CLOUD-829. Measured: two closes, one operation, `2026-08-21T02:37:51.492Z`.
# CLOUD-777 was marked Done and CLOUD-817 was closed as a Duplicate OF CLOUD-777,
# in the same operation — and CLOUD-817's own text was the finding that CLOUD-777's
# acceptance passed *vacuously*. So the row saying "this Done rests on a clause that
# cannot fail" was filed away as a restatement of the row it contradicts.
#
# A duplicate close is a claim that two rows say THE SAME THING. Here one row said a
# thing and the other said that thing is not true. The direction of the error is
# what matters: a duplicate close makes the closed row's content unreachable from
# the surviving row's, so the finding did not merely lose — it stopped being
# readable. `crates/batten/src/hook.rs` still names CLOUD-817 as the owner of an
# open decision, and following that pointer lands on a row filed under another.
#
# ─── WHAT THIS DECIDES, AND WHAT IT REFUSES TO PRETEND TO DECIDE ─────────────
#
# Whether two rows CONTRADICT is not computable, and a gate claiming to decide it
# would be estimating (non-negotiable rule 3). What is computable is narrower and
# covers the measured instance exactly: a duplicate close whose target changed into
# a completed state in the SAME OPERATION is a close that decided two things at
# once, and one of them was never argued.
#
# THE REFUSAL IS A DEMAND FOR A DECISION, NEVER A VERDICT ABOUT WHO WAS RIGHT. The
# gate cannot know which row was correct and says so: the two closes were decided
# together, and one of them has to be argued separately. That is what keeps this a
# gate rather than a judge (CLOUD-93). It moves no row and reverses no close.
#
# ─── THE WINDOW IS ONE SECOND, AND IT IS A BOUND RATHER THAN "SIMULTANEOUS" ──
#
# Implemented as equality of the two timestamps TRUNCATED TO THE SECOND, which is a
# strictly-less-than-one-second bound. No date arithmetic, deliberately: `date -d`
# is GNU-only and `mise-tasks/**` must stay BSD portable — `no-gnu-sed-in-place`
# and its siblings already deny that class of shortcut, and CI runs ubuntu and is
# structurally blind to all of them.
#
# THE HONEST LIMIT, stated rather than left to be discovered: two closes 400ms
# apart that straddle a second boundary are missed. Widening needs real duration
# arithmetic on two ISO strings, which is the thing portability rules out here. The
# measured case is same-second to the millisecond, so the default catches it, and
# `DUPLICATE_CLOSE_WINDOW` exists so a caller who has a wider case can say so
# rather than editing the predicate.
#
# Exit 0 no duplicate close shares an operation with its target's / 1 one does / 2
# could not look — matching `graph-check` and `released` so all three compose.
#
# Declared mutations (CLOUD-418), one per clause the suite must be able to lose.
# NO `|` MAY APPEAR IN A SED SCRIPT HERE. `mutant.sh` reads each row with
# `IFS='|' read -r slug script want`, so a pattern carrying its own `|` shifts every
# field after it — measured on this file's first three declarations, which all
# targeted a line containing `||` and came back `unappliable`, `inert` and
# `names-no-case` respectively, one per failure shape the tool distinguishes. Each
# mutation therefore names a line with no `||` in it, which is a constraint on WHICH
# line to corrupt rather than on what to prove.
#MUTANT window-never-compares|s@^\treport "$id" "duplicate-closed-with-its-target@\ttrue "$id" "@|a duplicate close in the same operation as its target's close is refused
#MUTANT absent-key-reads-as-clean|s@^any_key=.*@any_key=1@|a set with no duplicateOf key anywhere is could not look
#MUTANT target-outside-the-set-passes|s@^in_set() .*@in_set() { true; }@|a duplicate whose target was not piped is unjudgeable
set -uo pipefail

# One second, expressed as the number of leading characters of an ISO-8601
# timestamp that must match: `2026-08-21T02:37:51` is 19.
window="${DUPLICATE_CLOSE_WINDOW:-19}"

if ! payload=$(cat) || [[ -z "${payload//[[:space:]]/}" ]]; then
	echo "::error:: duplicate-close-check: stdin is empty; expected get_issue payload(s)" >&2
	exit 2
fi
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$payload" 2>/dev/null) ||
	! jq -e 'type == "array" and length > 0' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: duplicate-close-check: stdin is not a get_issue payload set. Recover it with \`mise run board-payloads <id>...\`, which reads this session's own results rather than text an agent re-typed (CLOUD-526)." >&2
	exit 2
fi

# Byte-stable ordering everywhere: numeric by issue number, as every board gate here
# does, so re-running produces the same bytes.
by_num() { sort -t- -k2,2n; }
ids=$(jq -r '.[].id // empty' <<<"$issues" | by_num)
id_index=$'\n'"$ids"$'\n'
in_set() { [[ "$id_index" == *$'\n'"$1"$'\n'* ]]; }

violations=0
unjudgeable=0
# Pointer-only per non-negotiable rule 4: the two keys and the two timestamps.
# NEVER a line of either body, and specifically never the sentence that made one row
# contradict the other — that sentence is the whole reason this row exists, and
# echoing it would put the content this gate protects into a log.
report() {
	echo "$1 $2" >&2
	violations=$((violations + 1))
}
unjudged() {
	echo "$1 $2" >&2
	unjudgeable=$((unjudgeable + 1))
}

# THE ANTI-VACUITY TERM, and it is the same one `graph-check` draws on `blockedBy`
# and `released` on `attachments`: a caller who projected the relation away gets
# zero duplicates, an unconditional pass, and a verdict over a field it never saw.
# An explicit `null` is DATA and is judged; only a set where NO payload carries the
# key at all is could-not-look.
#
# Keyed to a pseudo-id rather than per row, because the property is of the piped
# SET. A per-id line would convert every row in a projection-free sweep into a
# finding, which is the shape `graph-check`'s own header warns about.
any_key=$(jq -r '[.[] | select((try (.relations | has("duplicateOf")) catch false))] | length' <<<"$issues" 2>/dev/null) || any_key=0
if [[ -z "$any_key" ]] || [[ "$any_key" -eq 0 ]]; then
	unjudged "graph" "unjudgeable-duplicateof (no payload carries the key — re-fetch with get_issue(includeRelations: true))"
	echo "::error:: duplicate-close-check: $unjudgeable payload set(s) could not be judged" >&2
	exit 2
fi

# `completedAt` is the tracker's own stamp for entering a completed type, and
# `canceledAt` for entering a canceled one — a Duplicate is a canceled type. Both are
# read from the ROW'S OWN payload, so nothing here infers a transition from a
# column: a row's history is the tracker's answer, not this gate's reconstruction.
while IFS=$'\t' read -r id closed_at target; do
	[[ -n "$id" ]] || continue
	[[ "$target" != - && "$target" != null ]] || continue
	# A close with no stamp cannot be compared to anything. That is could-not-look
	# about this row rather than a pass: the field the predicate turns on is absent.
	[[ "$closed_at" != - && "$closed_at" != null ]] || {
		unjudged "$id" "unjudgeable-close-time (duplicateOf $target, and this row carries no canceledAt)"
		continue
	}
	in_set "$target" || {
		# The caller chose the closure, exactly as `graph-check` says of an edge
		# leaving the piped set: a target that was not piped is a question nobody
		# asked, never a clean answer.
		unjudged "$id" "unjudgeable-duplicate-target ($target not in the piped set)"
		continue
	}
	target_at=$(jq -r --arg t "$target" '.[] | select(.id == $t) | .completedAt // empty' <<<"$issues" 2>/dev/null | head -n1)
	[[ -n "$target_at" ]] || continue
	closed_at=${closed_at:0:$window}
	target_at=${target_at:0:$window}
	[[ "$closed_at" = "$target_at" ]] || continue
	report "$id" "duplicate-closed-with-its-target ($target completed at $target_at, this row closed at $closed_at)"
	# `-` FOR AN ABSENT FIELD, NEVER THE EMPTY STRING. Tab is whitespace to `read`, so
	# consecutive tabs COLLAPSE and an empty middle column shifts every field after it
	# left — measured: a row with no `canceledAt` put its `duplicateOf` target into the
	# timestamp variable and left the target empty, so the row read as "not a duplicate"
	# and passed. A placeholder keeps the column count fixed whatever is null.
done < <(jq -r '.[] | [(.id // "-"), (.canceledAt // "-"), (.relations.duplicateOf.id // .relations.duplicateOf // "-")] | @tsv' <<<"$issues" 2>/dev/null | by_num)

if [[ "$unjudgeable" -ne 0 ]]; then
	echo "::error:: duplicate-close-check: $unjudgeable row(s) could not be judged — the set does not answer the question" >&2
	exit 2
fi
if [[ "$violations" -ne 0 ]]; then
	echo "::error:: duplicate-close-check: $violations duplicate close(s) decided in the same operation as the target's own close. The gate does not know which row was right, and is not claiming to: what it refuses is TWO decisions taken as one. Argue the close on its own — either the rows really do say the same thing, or the closed one carries a finding about the survivor and needs reopening." >&2
	exit 1
fi
echo "duplicate-close-check: no duplicate close shares an operation with its target's ($(printf '%s' "$ids" | grep -c . || true) row(s))"
