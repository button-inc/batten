#!/usr/bin/env bash
#MISE description="Gate: run every board gate over one payload set and report the set of refusals (reads get_issue payloads on stdin or from BOARD_PAYLOADS_DIR) — CLOUD-825"
#
# THE GATES WERE NEVER MISSING. Seven exist, every one a pure function of
# `get_issue` payloads on stdin, and they already compose: `released` calls
# `graph-check` by path, `graph-check` calls `ready-lint`, `in-progress-drain`
# calls `landed-check`. What was missing is a caller. Two of the three roots
# were never pulled, and the third — `released`, wired into `release-plz.yml` on
# every tag — is invoked as `mise run released "$tag" </dev/null`, which takes
# its refs-only arm and RETURNS before the `graph-check` invocation. So the
# composition exists, is wired, runs, and is handed nothing to decide over.
#
# This is that caller and nothing else. It re-derives no gate's predicate: every
# one is invoked by path with JSON on stdin and its exit code read as the
# three-valued channel it publishes, which is the house pattern
# `board-write-record`, `claim-check` and `released` already use. A second sweep
# beside `released` -> `graph-check` -> `ready-lint` would be CLOUD-351's shape
# at the caller layer — two sweeps over one board, only the newer consulted.
#
# THE REPORT IS A SET, NOT A FIRST FAILURE. A sweep that stopped at the first
# refusing gate would make the second dissonance invisible until the first was
# fixed, and the next look is not free: CLOUD-782 measured `get_issue` at ~4.5k
# tokens per issue to decide on ~1.6k, because it takes no field selection and
# is the only source of `attachments`. One fetch, N gates is what makes the
# whole thing affordable, so every gate runs and the report names each refusal.
#
# COULD-NOT-LOOK IS A PROBLEM, NEVER A PASS, and it OUTRANKS a refusal. Empty
# stdin, a projected-away field, a capped evidence file: each means the sweep
# did not happen, and reporting that as clean is the vacuous pass CLOUD-251
# names. `graph-check`'s ordering, not `spec-ref-check`'s, because a composer
# that could not look has said nothing about any of its members.
#
# EFFECT IS `read`. It decides and reports; it MOVES NO ROW. That asymmetry is
# the safety property rather than an omission: a sweeper authorised to write
# would be a board-editing robot deciding from a snapshot, and
# `board-payloads`'s own header records the failure it recovers — structure
# faithfully, freshness not at all, so a recovered `status` may be stale.
# Recover the structure from the cache; re-read a row before deciding its state.
#
# NO SCHEDULE, deliberately (CLOUD-825 §5). Whether this also runs on a cron, at
# Stop, or as a `land` postlude is a trigger question with its own cost —
# CLOUD-812 measured 96 idle cron ticks/day flooring at ~2,900 billed min/month.
# Ship the caller; file the trigger.
#
# Usage: mise run board-sweep [--payloads <file|->] [--tag <tag>] [--pulls <file>]
#
# With no `--payloads`, the set is `$BOARD_PAYLOADS_DIR/*.json` when that
# directory holds any, and stdin otherwise. `-` forces stdin.
#
# Exit 0 the board is coherent / 1 dissonance named / 2 could not look.
#
# Declared mutations (CLOUD-418), one per clause the suite must be able to lose.
# `@` delimits each sed script and the rows are `|`-separated, so a script may
# carry no `|` of its own — which is why this corrupts the comparison rather
# than the `||` that follows it.
#MUTANT empty-set-is-clean|s@^\[\[ "$count" -gt 0 \]\]@[ "$count" -ge 0 ]@|an empty payload set is COULD NOT LOOK
#MUTANT gate-two-laundered|s@^\t\tunjudgeable=@\t\trefusals=@|a gate exiting 2 is not laundered into the refusal lane
#MUTANT drain-not-invoked|s@^run_gate in-progress-drain@true in-progress-drain@|a landed-but-In-Progress row is named by in-progress-drain
#MUTANT released-fed-nothing|s@^\trun_gate released.*@\trun_gate released "$here/released.sh" "$tag" </dev/null@|a payload set reaches graph-check behind released
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || {
	echo "::error:: board-sweep: not a git repository, so no gate below can resolve a ref" >&2
	exit 2
}

here="$(dirname -- "${BASH_SOURCE[0]}")"

payloads="${SWEEP_PAYLOADS:-}"
tag="${SWEEP_TAG:-}"
pulls_file="${SWEEP_PULLS:-}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--payloads)
		payloads="${2:-}"
		shift 2
		;;
	--tag)
		tag="${2:-}"
		shift 2
		;;
	--pulls)
		pulls_file="${2:-}"
		shift 2
		;;
	*)
		echo "::error:: board-sweep: unknown argument \"$1\". Usage: mise run board-sweep [--payloads <file|->] [--tag <tag>] [--pulls <file>]" >&2
		exit 2
		;;
	esac
done

# THE PAYLOAD SOURCE IS `board-payloads`' OUTPUT DIRECTORY, not a second
# recovery path (CLOUD-782 is the one authority on where a payload comes from).
# It writes one file per id rather than a stream, so assembling the array is
# this caller's job and not a re-derivation of anything.
# THE SOURCE IS CHOSEN BEFORE ANYTHING IS READ, and that ordering is the whole
# of it. Deciding by `[ -t 0 ]` does not work here: a task-runner call has no tty
# on stdin whether or not anything was piped, so the tty test reads "a caller
# piped something" every time, and a bare `mise run board-sweep` then BLOCKS on a
# stdin nobody is going to close. Look at the directory first, which is a
# question the filesystem answers immediately.
dir="${BOARD_PAYLOADS_DIR:-$(git rev-parse --git-dir)/batten-payloads}"
if [[ -n "$payloads" ]]; then
	if [[ "$payloads" = - ]]; then
		raw=$(cat)
	else
		[[ -r "$payloads" ]] || {
			echo "::error:: board-sweep: cannot read $payloads" >&2
			exit 2
		}
		raw=$(cat -- "$payloads")
	fi
elif compgen -G "$dir/*.json" >/dev/null 2>&1; then
	# `board-payloads` (CLOUD-782) writes one file per id rather than a stream,
	# so assembling the array is this caller's job. It is not a second recovery
	# path: that task stays the one authority on where a payload comes from.
	raw=$(cat -- "$dir"/*.json)
else
	raw=$(cat)
fi

issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$raw" 2>/dev/null) || {
	echo "::error:: board-sweep: the payload set is not JSON. Recover it with \`mise run board-payloads <id>...\`, which reads this session's own \`get_issue\` results rather than text an agent re-typed (CLOUD-526)." >&2
	exit 2
}

count=$(jq 'length' <<<"$issues" 2>/dev/null) || count=0

# THE ANTI-VACUITY TERM, and it is the one a composer gets wrong. An empty set
# runs every gate below, every one of them finds nothing to refuse, and the
# sweep reports the board coherent having looked at no row at all — which is
# exactly the `</dev/null` defect this task exists to fix, reproduced by its own
# remedy one level up.
[[ "$count" -gt 0 ]] || {
	echo "::error:: board-sweep: the payload set is empty, so no gate below can decide anything. That is COULD NOT LOOK, never a clean board — pipe \`get_issue\` payloads, or run \`mise run board-payloads <id>...\` first." >&2
	exit 2
}

refusals=0
unjudgeable=0

# Pointer-only per non-negotiable rule 4: the gate's name and its verdict. Each
# gate's own per-issue lines carry issue keys and rule ids and are passed
# through untouched; no gate here emits a line of an issue BODY, and this task
# adds none.
run_gate() { # run_gate <name> <command...>
	local name=$1
	shift
	local report status
	# BOTH STREAMS, and that is not tidiness. These gates do not agree on which
	# one carries a finding: `graph-check`, `landed-check`, `done-pr-check` and
	# `spec-ref-check` put per-issue lines on stderr and keep stdout for a
	# frontier or a tally, while `released` puts its per-issue verdicts —
	# including `REFUSED (<rule>)`, the one place `graph-check`'s answer surfaces
	# at all — on STDOUT. A composer reading stderr alone runs the whole chain
	# and then throws away the half of the report that names why.
	report=$("$@" 2>&1)
	status=$?
	case "$status" in
	0)
		echo "  $name ok"
		;;
	1)
		refusals=$((refusals + 1))
		echo "  $name REFUSED"
		[[ -z "$report" ]] || printf '%s\n' "$report" >&2
		;;
	*)
		# NEVER LAUNDERED INTO THE REFUSAL LANE. "This gate could not look" and
		# "this gate found dissonance" are different facts about the board, and
		# collapsing them makes an unrunnable gate read as a clean one the
		# moment somebody fixes the refusal beside it.
		unjudgeable=$((unjudgeable + 1))
		echo "  $name COULD NOT LOOK"
		[[ -z "$report" ]] || printf '%s\n' "$report" >&2
		;;
	esac
}

# The loop names TASKS and the files carry `.sh` (CLOUD-865), so the filename is
# built here rather than assumed equal to the task name — the same split
# `mutant` makes over `$MUTANT_GATES`.
for gate in released in-progress-drain done-pr-check spec-ref-check; do
	[[ -x "$here/$gate.sh" ]] || {
		echo "::error:: board-sweep: cannot run $here/$gate.sh. A gate that cannot run is not a pass — the sweep needs it, so this is 'could not look'." >&2
		exit 2
	}
done

echo "board-sweep: $count issue(s)"

# --- released -> graph-check -> ready-lint -----------------------------------
#
# THE REDIRECT THIS TASK EXISTS TO REPLACE. `released <tag>` with no stdin
# reports the refs a tag shipped and returns; only the stdin arm reaches
# `graph-check`, and through it `ready-lint` per Todo row. The tag defaults to
# the newest `v*` this checkout carries — and a checkout with no tags is could
# not look rather than a clean board, the same way `done-check` reads it, since
# a default CI checkout fetches no tags at all.
if [[ -z "$tag" ]]; then
	tag=$(git tag --list 'v[0-9]*' --sort=-version:refname | head -n1) || tag=""
fi
if [[ -z "$tag" ]]; then
	unjudgeable=$((unjudgeable + 1))
	echo "  released COULD NOT LOOK"
	echo "::error:: board-sweep: this checkout carries no \`v*\` tag, so \`released\` cannot resolve a range and \`graph-check\` behind it is never reached. Fetch tags, or pass --tag." >&2
else
	run_gate released "$here/released.sh" "$tag" <<<"$issues"
fi

# --- in-progress-drain -> landed-check ---------------------------------------
#
# Already self-sufficient: it gathers its own merged-PR evidence through
# `merged-pr-keys` when `DRAIN_MERGED_PRS` is unset, and turns `landed-check`'s
# exit 2 into its own. Nothing to supply but the payload set.
run_gate in-progress-drain "$here/in-progress-drain.sh" <<<"$issues"

# --- done-pr-check -----------------------------------------------------------
#
# The one gate needing evidence `get_issue` does not carry: a `.pulls` entry per
# PR its attachments name. Gathered here the way `in-progress-drain` gathers its
# own, and overridable by file so no test case touches the network. An absent
# state is deliberately exit 2 inside that gate — a Done granted over a PR
# nobody read is the defect it exists to refuse — so a failure to gather is
# could not look, and this task must not paper over it.
pulls="[]"
if [[ -n "$pulls_file" ]]; then
	pulls=$(cat -- "$pulls_file" 2>/dev/null) || pulls=""
elif command -v gh >/dev/null 2>&1; then
	pulls=$(gh pr list --state all --limit 500 --json number,state,isDraft 2>/dev/null |
		jq -c '[.[] | {number, state: (.state | ascii_downcase), draft: .isDraft}]') || pulls=""
fi
if [[ -z "$pulls" ]] || ! jq -e 'type == "array"' <<<"$pulls" >/dev/null 2>&1; then
	unjudgeable=$((unjudgeable + 1))
	echo "  done-pr-check COULD NOT LOOK"
	echo "::error:: board-sweep: no pull-request state to judge Done against. Supply --pulls <file> (a JSON array of {number,state,draft}), or make \`gh\` reachable." >&2
else
	# Every payload carries the whole list; `done-pr-check` selects by number, so
	# a per-issue projection here would be a second answer to a question that
	# gate already answers.
	with_pulls=$(jq -c --argjson pulls "$pulls" 'map(. + {pulls: $pulls})' <<<"$issues")
	run_gate done-pr-check "$here/done-pr-check.sh" <<<"$with_pulls"
fi

# --- spec-ref-check ----------------------------------------------------------
#
# The same pattern aimed at the tree rather than the board: a `CLOUD-<n> §N`
# citation in a tracked file naming a clause the issue lacks. It refutes and
# never confirms, so an issue cited but absent from this set is its exit 2 —
# which is why the payload set a caller assembles should cover what
# `git grep -hoE "CLOUD-[0-9]+'?s? §[0-9]+"` names, not just the active columns.
run_gate spec-ref-check "$here/spec-ref-check.sh" <<<"$issues"

if [[ "$unjudgeable" -gt 0 ]]; then
	echo "board-sweep: $unjudgeable gate(s) could not look — the board has not been judged" >&2
	exit 2
fi
if [[ "$refusals" -gt 0 ]]; then
	echo "board-sweep: $refusals gate(s) name dissonance above" >&2
	exit 1
fi
echo "board-sweep: every gate ran and none names dissonance ($count issue(s))"
