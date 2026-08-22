#!/usr/bin/env bash
#MISE description="PreToolUse hook body: deny `gh pr ready` unless verify and linear-check have both passed against this exact HEAD"
#
# Readying is the single event that starts CI, and it was the last step in the
# lifecycle with nothing behind it — the contract said "verify green, then
# linear-check, then ready" and relied on the agent remembering. A red run on a
# freshly-readied PR is the symptom, and by then CI minutes are already spent.
#
# The predicate is a receipt, not a claim: `verify` and `linear-check` each write
# one keyed to the HEAD they validated, and `linear-check`'s also records the
# `origin/main` it was linear against. This denies the call unless both exist for
# the current HEAD and that recorded `origin/main` still matches the local ref —
# so an amended commit, a rebase, or a `main` that moved under you all invalidate
# the receipt rather than silently passing.
#
# Receipts live in `.git/`, which is exactly right: they are per-clone facts
# about work in progress, never shared, and a fresh clone starts with none.
#
# Reads nothing from the network — a PreToolUse hook must be fast, so it compares
# against the `origin/main` ref already on disk. `linear-check` is what refreshes
# that ref, and it is one of the two things being demanded here.
#
# The third receipt is the landing lease (CLOUD-420). Readying is what starts CI,
# and the lease is what says only one branch may be spending CI on a landing at a
# time — so this is the same predicate as the other two, applied to the fleet
# rather than to the commit. It is also the free half of CLOUD-420: the runner's
# precondition catches this too, but only after a matrix has been dispatched and
# cancelled, while this costs nothing. `land-lock`'s heartbeat refreshes the
# receipt, so what is demanded is a lease that has not lapsed, not one that was
# ever taken.
#
# Fails OPEN on anything it cannot parse, and honours BATTEN_READY_GUARD_BYPASS=1.
set -uo pipefail

[[ -n "${BATTEN_READY_GUARD_BYPASS:-}" ]] && exit 0

raw=$(cat) || exit 0
cmd=$(printf '%s' "$raw" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -n "$cmd" ]] || exit 0

# Only `gh ... pr ready`. Quoted spans are neutralised first so a commit message
# naming the command is not the command.
scrubbed=$(printf '%s' "$cmd" | sed -E "s/'[^']*'/QUOTED/g; s/\"[^\"]*\"/QUOTED/g")
is_ready=0
while IFS= read -r seg; do
	read -r -a toks <<<"$seg"
	count=${#toks[@]}
	i=0
	while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do i=$((i + 1)); done
	# Look through wrapper programs so the EFFECTIVE program is judged, not the
	# wrapper. `mise exec -- gh pr merge` is a gh call — and in the web sandbox
	# the wrapper form is the only working form, so a guard that stops at the
	# wrapper token sees none of the gh calls that matter. Known wrappers only;
	# anything unrecognised keeps the fail-open posture.
	while :; do
		case "${toks[$i]:-}" in
		env | command | nice | stdbuf | timeout | xargs | sudo | doas)
			i=$((i + 1))
			# The wrapper's own flags, env assignments, and bare numeric
			# arguments (timeout's duration) precede the wrapped program.
			while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^(-|[A-Za-z_][A-Za-z0-9_]*=|[0-9]) ]]; do i=$((i + 1)); done
			;;
		mise)
			# Only `mise exec` / `mise x` run another program; `mise run` names a task.
			case "${toks[$((i + 1))]:-}" in
			exec | x)
				i=$((i + 2))
				# Tool pins (node@22), flags, and the `--` separator precede the program.
				while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^(-|[^ ]*@) ]]; do i=$((i + 1)); done
				;;
			*) break ;;
			esac
			;;
		*) break ;;
		esac
	done
	[[ "${toks[$i]:-}" = "gh" ]] || continue
	# `gh pr ready --undo` is the INVERSE action: it converts a PR back to draft,
	# which stops CI rather than starting it. Flags are stripped below so the verb
	# can be matched positionally, which made `--undo` invisible and got the guard
	# denying the one call that can only ever *save* CI minutes — including the
	# one `land` now makes when it bails, so a retry push costs nothing.
	has_undo=0
	for t in "${toks[@]:$((i + 1))}"; do
		[[ "$t" = "--undo" ]] && has_undo=1
	done
	words=()
	for t in "${toks[@]:$((i + 1))}"; do
		case "$t" in -*) ;; *) words+=("$t") ;; esac
	done
	n=${#words[@]}
	j=0
	while [[ "$((j + 1))" -lt "$n" ]]; do
		case "${words[$j]} ${words[$((j + 1))]}" in
		"pr ready" | "pr ready-for-review") [[ "$has_undo" = 1 ]] || is_ready=1 ;;
		esac
		j=$((j + 1))
	done
	# printf '%s\n', not '%s': without the trailing newline `read` returns false on
	# the final segment and the loop body never runs for it — for a single-segment
	# command that means the whole guard silently allows everything.
done < <(printf '%s\n' "$scrubbed" | sed -E 's/(\&\&|\|\||[;|&])/\n/g')

[[ "$is_ready" = 1 ]] || exit 0

git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0
head=$(git rev-parse HEAD 2>/dev/null) || exit 0
receipts="$git_dir/batten-receipts"

deny() {
	jq -n --arg r "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $r
    }
  }'
	exit 0
}

[[ -f "$receipts/verify.$head" ]] ||
	deny "Refused: no verify receipt for HEAD ${head:0:8}. Readying is the single event that starts CI, so it happens only after \`mise run verify\` is green against this exact commit — a red run on a freshly-readied PR means that step was skipped, and the CI minutes are already spent by then. Run \`mise run verify\` (background it), then retry. Bypass with BATTEN_READY_GUARD_BYPASS=1."

recorded_main=$(cat "$receipts/linear-check.$head" 2>/dev/null) ||
	deny "Refused: no linear-check receipt for HEAD ${head:0:8}. Run \`mise run linear-check\` immediately before readying — \`main\` moves constantly, and a branch that is not linear on the current \`main\` cannot fast-forward-land. Bypass with BATTEN_READY_GUARD_BYPASS=1."

current_main=$(git rev-parse origin/main 2>/dev/null) || exit 0
[[ "$recorded_main" = "$current_main" ]] ||
	deny "Refused: the linear-check receipt for HEAD ${head:0:8} was taken against origin/main ${recorded_main:0:8}, but origin/main is now ${current_main:0:8}. Rebase, re-run \`mise run verify\`, then \`mise run linear-check\` again. Bypass with BATTEN_READY_GUARD_BYPASS=1."

# The lease. Fail open on a detached HEAD or an unreadable clock, like every
# other unknown in this file — the runner's precondition is the backstop, and it
# is the one that costs money, so this half never needs to guess.
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || exit 0
[[ -n "$branch" ]] && [[ "$branch" != HEAD ]] || exit 0
now=$(date +%s 2>/dev/null) || exit 0

lease_expires=$(cat "$receipts/lease.${branch//\//-}" 2>/dev/null) ||
	deny "Refused: this clone does not hold the landing lease for '$branch'. Readying starts CI, and the lease is what keeps one branch at a time spending it — four concurrent matrices ran on 2026-08-12 while three sessions handed the lease around correctly (CLOUD-420). Don't ready by hand: run \`mise run land\` (background it), which acquires the lease and readies behind it. Bypass with BATTEN_READY_GUARD_BYPASS=1."

case "$lease_expires" in
'' | *[!0-9]*) exit 0 ;;
esac
[[ "$lease_expires" -gt "$now" ]] ||
	deny "Refused: the landing lease for '$branch' lapsed $((now - lease_expires))s ago, so another branch may already be landing. A lease is renewed by \`land\`'s heartbeat, so a lapsed one means that \`land\` is gone. Run \`mise run land\` (background it) rather than readying on top of a lease nobody is holding. Bypass with BATTEN_READY_GUARD_BYPASS=1."

# --- REBASE, DO NOT REPAIR -----------------------------------------------------
#
# The threat is not malice, it is an agent on a clone that predates the landing
# work reading its shape as breakage and repairing it back — a raced wait with no
# clock, a verdict that answers "no answer", a lease held by a live process. Each
# looks like a defect from an older tree, and each is the change. This is the one
# predicate that catches it BEFORE the rebase whose conflicts in `mise-tasks/land.sh*`
# and `tests/land*.bats` are exactly where "take ours" undoes it.
#
# THE LANDING COMMIT IS DERIVED, NOT STORED, and the chicken-and-egg is why. Its
# sha is minted by the commit that introduces this predicate, so no file that
# commit adds can name it; and a rebase or cherry-pick mints a different sha
# anyway, so a hardcoded value would be wrong in every clone that did not receive
# the exact original object. What IS stable in every clone is a fact of history:
# the commit that first ADDED the memory this same change ships.
#
# Read along `origin/main`, never HEAD. HEAD is the thing being judged — on the
# stale branch this exists to catch, the path is absent from HEAD's history
# entirely, so deriving from HEAD would answer "no landing commit" and fail open
# on precisely the case that matters. `origin/main` is already in hand two checks
# above, and `linear-check` — demanded above — is what refreshes it.
#
# `tail -1` takes the OLDEST addition, so a delete-and-re-add cannot move the
# epoch forward and quietly re-admit a stale base.
marker=".serena/memories/workflow/landing-loop.md"
landing=$(git log --diff-filter=A --format=%H "$current_main" -- "$marker" 2>/dev/null | tail -1) || exit 0
# FAIL OPEN while this clone's origin/main has never carried the landing commit.
# During rollout that is not an edge case, it is every clone.
[[ -n "$landing" ]] || exit 0

git merge-base --is-ancestor "$landing" HEAD 2>/dev/null ||
	deny "Refused: this branch's merge-base predates the landing commit ${landing:0:8}, where \`land\`, the lease and their suites took their current shape. Everything you are about to rebase through will look like breakage from here — a wait with no clock, a verdict that answers 'no answer yet', a lease held by a live process — and repairing it back is how the change gets undone one branch at a time. REBASE, DO NOT REPAIR: \`git fetch origin main && git rebase origin/main\`, take the incoming side in \`mise-tasks/land.sh*\` and \`tests/land*.bats\`, re-run \`mise run verify\`, then retry. Read \`mem:workflow/landing-loop\` first if any of it reads as a bug. Bypass with BATTEN_READY_GUARD_BYPASS=1."

exit 0
