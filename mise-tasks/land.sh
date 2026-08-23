#!/usr/bin/env bash
#MISE description="Land this branch's PR: rebase, verify, push, wait for CI, /fast-forward — lapping until it merges or a rebase conflicts"
#
# Workflow-contract step 4, and it drives the WHOLE loop rather than one lap of
# it. `main` advances constantly, so the fast-forward bot refuses the moment
# this branch stops being a direct descendant. That refusal is the design
# working: each lap rebases onto a little more landed work, so conflicts arrive
# one small resolvable increment at a time instead of accumulating until a
# branch cannot land at all.
#
# A lap is fetch → rebase → `verify` → `verified` → push → `ci-wait` →
# `/fast-forward` → read the answer, and a refusal simply starts the next one.
# Every lap re-verifies and re-waits because a rebase mints a new SHA and the
# receipts keyed to the old one are gone — that is the loop, not a re-run of an
# already-tested commit. `verified` reads the receipt keyed to this exact HEAD,
# which also carries the `origin/main` it was linear against, so there is no
# second linearity check here; a second copy would be a second authority.
# `ci-wait` makes landing a red PR structurally impossible. Both are called
# per-lap rather than declared as `#MISE depends`, because a dependency runs
# once and a loop needs them every time round.
#
# **The stops are the things bash cannot reason about**: a rebase that CONFLICTS,
# a local `verify` that fails, a CI run that comes back red on a branch whose
# `verify` was green, and — since CLOUD-323 — a PR body that defers a decision
# without naming the issue that owns it, which needs a human to file one. Everything else in a lap is mechanical, so
# this runs unattended and halts exactly at the steps that need a decision (AGENTS.md, "When you SHOULD still stop") — which is also the
# step frequent lapping keeps small. CLOUD-238: ending the lap and leaving the
# caller to rebase and retry was only half the design. Measured over one
# session, every refusal arrived out-of-band and was handled by hand, and from
# that the agent inferred landing was "a race I keep losing" and began batching
# rebase→verify→push→land into one command to close the window — optimising
# against the design, since batching removes no refusal and only makes each lap
# bigger. A loop a caller has to notice is a loop a caller will eventually
# mis-model, so the task laps itself and the inference has nowhere to start.
#
# The merge button is blocked on purpose: `main` only advances to a SHA that
# already passed CI. Commenting is the whole landing action, but the *result* is
# asynchronous, so the naive form is a comment plus a guessed `sleep`, which
# either reports too early or wastes time. Poll instead, with two exit
# conditions so it cannot hang: the PR reaches a terminal state, or the
# fast-forward workflow concludes anything but success.
#
# CLOUD-235 — the refusal condition used to be dead code, and the shape of the
# mistake is worth keeping: it filtered `commits/$sha/check-runs` for a run named
# `fast-forward`, where `$sha` is the PR head. But the bot triggers on
# `issue_comment`, and an `issue_comment` run attaches its check-run to the
# DEFAULT-BRANCH TIP, never to the PR head — two SHAs that differ by
# construction before a landing, so the filter always returned empty. (The
# workflow also grants no `checks: write`, so it could not have created one on
# any SHA.) A refusal is a PR comment plus a failed workflow-run conclusion, and
# nothing else. So the verdict is read from the run's `conclusion`: an exit code,
# not prose, which is the only kind of thing a gate may decide on. The task then
# claimed for months to have an exit condition it did not have, and polled
# forever the first time a refusal arrived.
#
# A lap's wait is a RACE between two answers (CLOUD-240). `ci-wait` answers "is
# this SHA green"; `main-watch` answers "is this SHA still landable". The moment
# `main` advances, the run in flight is already waste — its verdict cannot be
# used and the bot will refuse — so waiting it out to be told what is already
# knowable is the expensive way to learn nothing. Whichever answers first
# decides, and a `main-watch` win simply starts the next lap. The push that lap
# makes cancels the doomed run through the workflows' `concurrency:
# cancel-in-progress`, so nothing here cancels a run by hand.
#
# Two more economies, both from the same premise — a runner is metered and this
# sandbox is not:
#
#   * A lap whose HEAD already carries a `verify` receipt does not re-run
#     `verify`. A refusal with an unmoved `main` changes no bytes, and the
#     receipt is keyed to the exact commit, so re-proving it is work with a
#     known answer.
#   * A red CI converts the PR back to DRAFT before stopping. CI does not run on
#     drafts, so this closes the tap while the failure is diagnosed locally;
#     left ready, the next push from any source starts another run over a
#     failure nobody has fixed yet. `land` readies it again on the lap that
#     follows, which is the single event that spends the one confirming run.
#
# The poll is deliberately unbounded, like `ci-wait`: the fix for a hang is an
# exit condition that can actually fire, never a wall-clock timeout, which would
# only reintroduce the VM-reap gap. `LAND_MAX_LAPS` bounds the number of LAPS
# instead — a runaway backstop, not a timeout on any wait: hitting it means
# `main` is moving faster than a lap takes, which is a real condition a human
# should see. Run it backgrounded; several laps are normal and each costs a CI
# run, which is the price of the design, not waste.
#
# `set -e` is off on purpose: this is a poll, and a transient `gh` failure must
# cost one iteration rather than abort the landing. Every command whose failure
# would change the verdict is guarded by hand instead.
#
# MUTATION COVERAGE (CLOUD-418). `<slug>|<sed script>|<case name>`: applying
# the script to a throwaway copy of this file must turn the named case RED.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT lap-cap-may-read-as-stop|s/RUN THIS AGAIN/look/|names the continuing action
#MUTANT exit-codes-collapse|s/^readonly LAND_EXIT_RUNAWAY=5$/readonly LAND_EXIT_RUNAWAY=4/|CLOUD-399: the two exhaustions are told apart by CODE
#MUTANT declined-always|s/^\t\[\[ \"\$rc\" = 3 \]\]$/\ttrue/|red CI stops the lap without asking for the merge
# CLOUD-369. The admission predicates, each proven to discriminate rather than
# merely to exist. Case names carry no regex metacharacters: `mutant` passes the
# name to `bats --filter`, which reads it as a PATTERN, so a clause spelled
# `(b1)` matches nothing and the row reports `names-no-case` instead of a verdict.
#
# THE CONFLICT CLAUSE TAKES TWO ROWS, not one, because it has two halves that
# fail independently: `speculate` must RECORD the conflict it computed, and the
# admission must READ it. One row could only ever show that the pair works, not
# that either half does — and a half that stops discriminating is exactly how a
# mutation survives while its case still passes (measured on CLOUD-520, where a
# row neutering one half of a two-part predicate was caught SURVIVING).
#MUTANT admits-without-green|s/elif ! mise run checks-green "\$holder_head" >\/dev\/null 2>&1; then/elif false; then/|CLOUD-369 clause b1-neg — a holder whose CI answers RED admits nobody
#MUTANT admits-a-conflicting-base|s/^\t\tif \[\[ "\$admitted" = 0 \]\] \&\& \[\[ "\$spec_conflicts" = 1 \]\]; then$/\t\tif false; then/|CLOUD-369 clause e — a waiter whose base CONFLICTS is not admitted
#MUTANT admits-with-no-head|s/if \[\[ -z "\$holder_head" \]\]; then/if false; then/|CLOUD-369 clause b1-neg — a lease naming no head admits nobody
#MUTANT speculation-never-conflicts|s/^\t\tspec_conflicts=1$/\t\tspec_conflicts=0/|CLOUD-369 clause e — a waiter whose base CONFLICTS is not admitted
#MUTANT verdict-first-page-only|s/\[\[ \"\$ff_seen\" -lt 100 \]\] && break/break/|fell off the first page

set -uo pipefail

cd "${LAND_ROOT:-$(git rev-parse --show-toplevel)}" || exit 1

branch="${LAND_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
# THE OPEN PR FOR THIS BRANCH, AND ONLY AN OPEN ONE (CLOUD-465). A bare
# `gh pr view` answers with whatever PR this branch name has EVER had, in any
# state — so once a name has carried a merged PR, every later landing on that
# name binds to the merged one. That is the default shape here rather than an
# edge case: trunk-based development deletes the branch on merge (CLOUD-349)
# while the session harness pins an agent to one branch name for its whole
# engagement, so the second landing of any session recycles a merged name.
#
# Observed: after #366 merged, a new commit and a new PR #368 on the same name
# produced `could not re-draft #366`. What kept that from being worse was
# incidental — `redraft` runs before the wait loop and GitHub refuses to
# re-draft a merged PR, so the run died before reaching the terminal-state read
# below, which treats MERGED as landed and exits 0. A bound-merged PR is one
# refactor away from reporting a landing that never happened, and a false
# completion signal is the one thing this repository exists to refuse.
#
# `// empty` rather than a null: `--jq` prints the string "null" for a missing
# field, which is not empty and would sail past the guard as a PR number.
pr="${PR:-$(gh pr list --head "$branch" --state open --json number --jq '.[0].number // empty' 2>/dev/null)}"
if [[ -z "$pr" ]]; then
	echo "::error:: no open pull request for this branch, so there is nothing to land. Open one first: gh pr create --draft" >&2
	exit 1
fi
interval="${LAND_INTERVAL:-10}"
workflow="${LAND_WORKFLOW:-fast-forward.yml}"
# THE TWO BACKSTOPS BOUND DIFFERENT RESOURCES, AND USED TO BE PRICED AS IF THEY
# BOUND THE SAME ONE (CLOUD-399). A lap is METERED: it buys a CI matrix, measured
# at ~17 job-minutes. A lease wait is FREE: a conditional poll against a ref, no
# runner. Both defaulted to 8, which authorised ~2 runner-hours of metered spend
# against ~16 minutes of free waiting — the expensive budget draining first
# (measured on #302, 2026-08-12, four active sessions: 5 waits lost and 3 laps
# entered in 22 minutes). The trade these defaults must express is MANY FREE
# WAITS, FEW PAID LAPS.
#
# Neither is a clock. `max_laps` counts laps, `max_waits` counts whole lease turns
# lost; a wall-clock cap on either reintroduces the VM-reap gap and lands as a
# false "refused" on a slow bot (`mem:workflow/landing-loop`).
max_laps="${LAND_MAX_LAPS:-2}"
# Consecutive whole lease waits lost before landing reports the fleet saturated.
# ~64 is the queue depth a contended fleet reaches — ~2h at the observed 2-5
# minute lease turn — and waiting that long costs nothing but wall clock.
max_waits="${LAND_LOCK_MAX_WAITS:-64}"
# How many consecutive passes may end with no readable answer from the bot before
# this stops (CLOUD-413). A count of unreadable answers, not a clock on the poll.
max_unknowns="${LAND_ANSWER_MAX_UNKNOWNS:-3}"
# How many provisioning transients may be absorbed by re-running the failed jobs
# before this stops (CLOUD-483). A count of absorbed transients, not a clock on
# how long they keep happening: three in a row is a broken world, not a flake,
# and the stop says so rather than re-running forever.
max_transients="${LAND_MAX_TRANSIENTS:-3}"

# EXIT CODES, NOT PROSE, ARE WHAT A CALLER DECIDES ON (CLOUD-399). Every stop
# used to be `exit 1`, so a saturated fleet ("wait, and land later — nothing is
# wrong") and a runaway branch ("`main` moves faster than a lap takes — look")
# were indistinguishable to anything but a human reading stderr. A fleet driver
# keying on a status could not tell "retry me later" from "I am broken", which is
# the same class of defect as reading a non-answer as an answer.
#
# The two exhaustions therefore get their OWN codes, and `die` keeps 1 so the
# other eighteen call sites are unchanged. The house-style 0/1/2/3 table governs
# the CLI's verbs; `land` is a lifecycle task, and these are additive stop
# reasons above that range rather than a re-spelling of it.
readonly LAND_EXIT_FLEET_SATURATED=4
readonly LAND_EXIT_RUNAWAY=5

die_with() {
	local code="$1"
	shift
	echo "::error:: land: $*" >&2
	exit "$code"
}

die() {
	die_with 1 "$@"
}

# THE ROSTER, GUARDED WHERE AN EXIT CAN ACTUALLY EXIT (CLOUD-467). `graded_runs`
# reads `$CI_REQUIRED_CHECKS`, and its abort on an unset one used to be swallowed
# by a `|| n=0` written for a transient API failure — so the one input this task
# cannot compute became `0`, which both call sites read as "this head carries no
# graded run": the branch that FIRES THE READY THAT STARTS CI.
#
# The guard belongs HERE and not in that function, which is the correction that
# matters. Both call sites wrap it in `$( )`, so a `die` inside it exits the
# SUBSHELL only — the lap then continues with an empty reading and falls into the
# unbounded answer poll, turning a fail-closed guard into a hang. Measured: the
# suite stopped terminating at all.
#
# `checks-green` guards the same variable for the same reason, and the two are
# deliberately paired, so opposite behaviour on a missing roster is exactly the
# drift that pairing exists to prevent.
[[ -n "${CI_REQUIRED_CHECKS:-}" ]] ||
	die "CI_REQUIRED_CHECKS is unset — run this through \`mise run land\`, which is where the required set is declared. Readying a PR against an unknown roster would spend a matrix to answer a question this task could not ask."
# The answered set is guarded HERE for exactly the same reason and in exactly the
# same place (CLOUD-376, CLOUD-467): `graded_runs` reads it, both call sites wrap
# that in `$( )`, and a `:?` abort inside a subshell exits the subshell only —
# turning a fail-closed guard into an empty reading, which both call sites read as
# "this head carries no graded run". That is the branch that fires the ready.
[[ -n "${CI_ANSWERED_CONCLUSIONS:-}" ]] ||
	die "CI_ANSWERED_CONCLUSIONS is unset — run this through \`mise run land\`, which is where the answered set is declared. An empty set makes every conclusion an answer, which is a false green in a new spelling."

# Stopping on a red run without closing the tap is a leak this exists to plug:
# CI skips drafts, so re-drafting is what stops the next push — from any source
# — spending another runner on a failure nobody has fixed yet.
redraft() {
	gh pr ready "$pr" --undo >/dev/null 2>&1 &&
		echo "land: re-drafted #$pr — ${1:-CI does not run on drafts, so nothing more is spent until this is fixed locally}"
}

# --- the landing lease (CLOUD-393) ----------------------------------------
#
# Only one branch at a time may spend CI on a landing attempt. Measured before
# this existed: 248 attempts in 30 minutes produced 5 merges, because every
# branch that finished CI had already gone behind by the time it asked. Waiting
# is free; a lost lap costs a whole CI matrix, and this converts the second into
# the first.
#
# `heartbeat_pid` renews the lease for as long as this lap holds it. It must be
# reaped on EVERY way out — the merged path, a die, a signal — or a dead session
# leaves a beating lease that nobody can steal, which is the one failure mode
# that would wedge the fleet rather than merely slow it.
heartbeat_pid=
# CLOUD-434: a group TERM is a request, not a fact — it demonstrably missed
# grandchildren twice in one loaded gate run, and the survivors held bats'
# output fd and wedged the whole gate. So after every TERM-and-wait, the reap
# verifies the GROUP is gone — `kill -0 -- -pgid` answers for any surviving
# member, where `wait` proves only that the leader died — and escalates a
# survivor to SIGKILL rather than trusting it to die eventually. Run AFTER the
# wait, so a group exiting gracefully is never escalated for being mid-exit.
reap_residue() {
	! kill -0 -- -"$1" 2>/dev/null || kill -9 -- -"$1" 2>/dev/null
}

# THE RENDEZVOUS (CLOUD-383). `wait -n` needs bash 4.3 and its PID-list form
# needs 5.1; macOS ships bash 3.2 as `/bin/bash` and `mise registry` carries no
# bash, so this file was the last bash-4 construct in the tree — CLOUD-282 fixed
# every other macOS blocker and could not touch it because another session held
# the file. `darwin-link` is a required check, so this is not hypothetical.
#
# A FIFO is the portable form of the same wait: each racer writes one byte AFTER
# writing its rc file, and the parent's blocking read returns as soon as either
# does. That ordering is what preserves the invariant both call sites read — the
# loser is killed before it reaches its `echo`, so its rc file stays EMPTY, and
# "empty means this racer never finished" still decides the lap.
#
# A racer that finishes second may block writing to a FIFO nobody is reading any
# more. That is harmless and deliberate: the group kill below reaps it, and its
# rc file was already written before the write it is blocked on.
# RETURNS non-zero; it does NOT die. Every caller wraps it in a command
# substitution, and a `die` inside `$( )` exits the SUBSHELL — the lap would carry
# on with an empty fifo path and both rc files empty, reporting "no verdict" over
# a race that never ran. `graded_runs` carries the same warning for the same
# reason (CLOUD-467); this is that defect rediscovered by writing it again.
new_rendezvous() {
	local f
	f="$(mktemp -u)" || return 1
	mkfifo "$f" 2>/dev/null || return 1
	printf '%s' "$f"
}
# The winner's token, set by `await_first` in THIS shell (see there).
AWAIT_WINNER=""
await_first() {
	# The byte NAMES THE WINNER, and the caller voids the loser's rc with it
	# (CLOUD-510). It used to be discarded — "which racer won is read from the rc
	# files" — and that reading is only correct while the loser leaves no file.
	#
	# The loser usually leaves none, because the group kill lands before its
	# `echo $? >` runs; measured, and that is why this was safe enough to ship.
	# But "usually" is doing load-bearing work there: the two racers are answering
	# at the same instant by construction, so nothing stops the loser finishing on
	# its OWN — `ci-wait` returning a red verdict in the same breath as
	# `main-watch` reporting main moved. Then the rc file is non-empty, honestly
	# written, and about a run whose verdict is already void; the arm below reads
	# it and stops the landing over a run the next lap supersedes anyway.
	#
	# Emptiness is a proxy for "this racer lost". The token is the fact itself,
	# and it is minted by the rendezvous that actually decided the race. An empty
	# token — an unreadable FIFO — leaves both codes as they are, so a caller that
	# cannot learn the winner falls back to exactly today's reading.
	#
	# THROUGH A GLOBAL, NEVER A COMMAND SUBSTITUTION, and that is not style. The
	# read here BLOCKS, and `$( )` runs its body in a subshell: bash defers a trap
	# until the current foreground command finishes, so with the read one level
	# down a `land` killed mid-race would never reach `on_exit` — it would hang on
	# the FIFO with its watchers still polling, which is the leak the trap exists
	# to close. Measured: it hung `tests/land.bats`'s "a land killed mid-race
	# takes its watchers with it". Assigning in THIS shell keeps the read
	# interruptible and the trap prompt.
	AWAIT_WINNER=""
	read -r AWAIT_WINNER <"$1" || true
	rm -f "$1"
}
# The live race pids, so the EXIT trap can reap what an in-flight race spawned.
# A land that dies THROUGH the trap — a TERM, a die inside a wait — used to
# reap only the heartbeat, and a measured 10 minutes of orphaned gh-polling
# ci-wait followed (CLOUD-434's review finding). Two scalars, not a list: the
# races are sequential and at most a pair wide, and scalars need no
# word-splitting. Cleared after every inline reap, so the trap can never kill
# a recycled pid from a race that already ended.
race_pid_a=
race_pid_b=
reap_races() {
	local p
	for p in "$race_pid_a" "$race_pid_b"; do
		[[ -n "$p" ]] || continue
		kill -- -"$p" 2>/dev/null || true
		reap_residue "$p"
	done
	race_pid_a=
	race_pid_b=
}
drop_lease() {
	reap_races
	if [[ -n "$heartbeat_pid" ]]; then
		kill -- -"$heartbeat_pid" 2>/dev/null || true
		wait "$heartbeat_pid" 2>/dev/null
		reap_residue "$heartbeat_pid"
		heartbeat_pid=
		# CLOUD-451's census, and this line is what keeps it honest. The
		# heartbeat records a beat per 30s and an `x` on every path where IT
		# chooses to stop — but the commonest stop is not one of those: a land
		# that finishes normally reaches here and KILLS it, so the loop never
		# runs another statement and its last record stays an `h`. Left that
		# way, every successful landing would afterwards read as "the container
		# died under active work", which is the false positive that would
		# wrongly license the mechanism CLOUD-515 removed for want of evidence.
		#
		# Written HERE and never from the heartbeat's own trap, per CLOUD-491:
		# a trap runs on the container kill too, and an `x` from one would erase
		# the only distinction the census draws. This is `land` recording that
		# IT chose to stop its child, which is exactly the event an `x` means.
		census="$(dirname -- "${BASH_SOURCE[0]}")/reclaim-census.sh"
		[[ -x "$census" ]] && "$census" note x land-stopped >/dev/null 2>&1 || true
	fi
	mise run land-lock release >/dev/null 2>&1 || true
}

# A lap reads `origin/main` twice now — once to rebase onto, once inside the
# hold to confirm it has not moved (CLOUD-369) — and the failure is the same
# failure both times. One definition, so the two cannot drift into disagreeing
# about what an unreachable remote means.
# `--prune` IS LOAD-BEARING, NOT TIDINESS (CLOUD-345). When a PR merges the head
# branch is deleted, but a plain fetch never removes `refs/remotes/origin/<branch>`
# — so the tracking ref survives, still naming the SHA that landed. Reusing that
# branch name then hits a `--force-with-lease` whose expectation names a ref the
# remote does not have, and the push is rejected as `stale info` FOREVER: no
# number of laps clears it, because every lap re-fetches without pruning.
#
# Measured 2026-08-11, and it misled three readers at once: this push ("someone
# else moved the branch" — nobody had), the harness stop hook ("20 unpushed
# commits" on a branch whose true unlanded set was 1), and `land`'s own post-merge
# delete ("already gone, or the remote refused" — both halves were live).
#
# It belongs here rather than in each reader: the readers are not all ours, and
# only the landing loop knows when the ref went stale.
fetch_main() {
	git fetch -q --prune origin main ||
		die "cannot fetch origin/main; read mem:github-access before concluding the network is blocked."
}

# A wait is a lap that spent no CI, and there are now two ways to have one: the
# lease was held by someone else, or it was won over a `main` that had moved. Both
# must refund the lap — a busy fleet would otherwise exhaust LAND_MAX_LAPS on
# waiting alone and give up without ever having attempted — and both must count
# toward the wait backstop, because "never counted" is how a loop becomes
# unbounded with no condition that can fire.
charge_wait() {
	lap=$((lap - 1))
	lease_waits=$((lease_waits + 1))
	[[ "$lease_waits" -le "$max_waits" ]] ||
		die_with "$LAND_EXIT_FLEET_SATURATED" \
			"never won the landing lease in $max_waits attempts, having spent no CI matrix. The fleet is saturated: wait, or land later. Run \`mise run land-lock-check\`, which tells that apart from a wedged lease (a ref nothing legitimate wrote) — they look identical from here."
}

# The same accounting for a pass that got no READABLE ANSWER from the bot
# (CLOUD-413, CLOUD-414). It is `charge_wait`'s shape for the same reason: the
# pass spent nothing, so charging it to the lap budget would let a rate-limited
# bot exhaust the budget that exists to catch "main moves faster than a lap
# takes" — and would report that diagnosis, which is what CLOUD-413 measured
# being wrong twice over across 24 laps.
#
# An unknown re-ask laps, and on an unmoved `main` that lap is free by
# construction: `verified` short-circuits on the unchanged HEAD, `graded_runs` is
# non-zero because the head just graded green so neither the ready nor the
# `--undo` re-fire can fire, and the force-push moves nothing so no
# `synchronize` event and no run. The lap costs a lease acquire, a fetch and one
# comment. That is what makes re-asking the right move rather than a spend.
#
# A count, never a clock — the bound `mem:github-rest-etiquette` calls the one
# place a retry cap belongs.
charge_unknown() {
	lap=$((lap - 1))
	answer_unknowns=$((answer_unknowns + 1))
	[[ "$answer_unknowns" -le "$max_unknowns" ]] ||
		die "the fast-forward bot gave no readable answer $max_unknowns times running on #$pr (${sha:0:8}). Nothing about this branch is wrong and \`main\` has not moved under it.${rate_reset_note:-} Do: mise run land"
}

# HONOUR THE NUMBER THE SERVER STATES (CLOUD-413). Measured on PR #323: 24 laps
# across three invocations, never merging, and not one lap failed for any of the
# three reasons `land` stops on. Several refusals were a 403 rate limit, which
# `land` could not tell from "main moved" — so its response to being rate-limited
# was to generate more of exactly the request that was rate-limited, each retry
# costing a `verify`, a CI run and another comment.
#
# `mem:github-rest-etiquette` names this in as many words: a 4xx/5xx means fix the
# interaction rather than retry blindly, and repeated secondary-limit failures get
# backoff bounded by a COUNT — "the one place a retry cap belongs". That cap is
# `$max_unknowns` above, unchanged. What was missing is the delay, and a guessed
# margin is the wrong shape when the server states the number:
#
#   retry-after: N                            wait N
#   x-ratelimit-remaining: 0 + …-reset: EPOCH wait until EPOCH
#   neither                                   a floor, because some delay beats none
#
# NOT A WALL CLOCK ON ANYTHING. This is a delay before re-asking, on a path that
# has already decided to lap; no wait in this task gains a deadline from it.
rate_limit_pause() {
	local headers="$1" retry remaining reset now secs
	retry=$(sed -n 's/^[Rr]etry-[Aa]fter:[[:space:]]*\([0-9]*\).*/\1/p' <"$headers" | head -1)
	remaining=$(sed -n 's/^[Xx]-[Rr]ate[Ll]imit-[Rr]emaining:[[:space:]]*\([0-9]*\).*/\1/p' <"$headers" | head -1)
	reset=$(sed -n 's/^[Xx]-[Rr]ate[Ll]imit-[Rr]eset:[[:space:]]*\([0-9]*\).*/\1/p' <"$headers" | head -1)
	now=$(date -u +%s)
	secs=""
	if [[ -n "$retry" ]] && [[ "$retry" -gt 0 ]] 2>/dev/null; then
		secs="$retry"
		rate_reset_note=" The API asked for ${retry}s (retry-after)."
	elif [[ "${remaining:-1}" = 0 ]] && [[ -n "$reset" ]] && [[ "$reset" -gt "$now" ]] 2>/dev/null; then
		secs=$((reset - now))
		# The reset TIME, which the code has and used to throw away in favour of
		# telling the human to go run `gh api rate_limit` for it.
		rate_reset_note=" The rate limit resets at $(date -u -d "@$reset" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "epoch $reset")."
	else
		secs="${LAND_RATE_FLOOR:-60}"
		rate_reset_note=" The response stated no limit headers."
	fi
	# A stated reset can be far away; the count is what bounds the loop, so a
	# single pause is capped only to keep one lap from swallowing the whole
	# budget in one sleep.
	[[ "$secs" -le "${LAND_RATE_PAUSE_MAX:-900}" ]] || secs="${LAND_RATE_PAUSE_MAX:-900}"
	echo "land: lap $lap — backing off ${secs}s before re-asking;${rate_reset_note}" >&2
	sleep "$secs"
}

# --- speculative linearization (CLOUD-369) -----------------------------------
#
# PRE-WARMING IS A LINEARIZATION, NOT A REFRESH. A waiter that rebases onto
# `origin/main` warms nothing: the branch holding the lease is about to replace
# that commit, so the waiter is stale again the moment it wins — which is the
# cold window this exists to close, paid earlier and no cheaper. The `main` worth
# linearizing against is the one about to EXIST, and the lease publishes it as
# `head:`.
#
# Done while waiting, this costs nothing. Local execution is free and CI does not
# run on drafts, so a waiter can rebase, resolve and re-verify indefinitely for
# the price of CPU this sandbox does not meter.
#
# THE HAZARD, AND THE INVARIANT THAT ANSWERS IT. A speculative rebase puts
# ANOTHER BRANCH'S unlanded commits into this branch's history. If that branch
# then fails to land, a fast-forward from here would carry them onto `main` —
# landing somebody else's unmerged work as a side effect of ours, which is a far
# worse failure than the cold window. `origin/main --is-ancestor HEAD` does NOT
# catch it: the speculated base is itself a descendant of main, so that check
# passes for exactly the case that must fail.
#
# So the bet is recorded and settled, never assumed:
#
#   spec_base  the commit we rebased onto; the bet is "this becomes main"
#   spec_undo  our HEAD before the rebase; the bet losing costs a reset to it
#
# and `settle_speculation` runs at the TOP of every lap, before anything can
# push. Won (the base is now an ancestor of `origin/main`) keeps the tree; lost
# resets it. There is no path from a losing bet to a push, which is the property
# that makes speculating safe rather than merely fast.
#
# AND THE THIRD READING, WHICH THE FIRST VERSION DID NOT HAVE (CLOUD-495). "Won"
# and "lost" are both statements about `main` MOVING, so a holder that abandons
# while `main` stays put falls through to "pending" — and pending returned 0
# forever. Measured: a holder whose CI died in a provider incident held the lease
# going nowhere, a sibling linearized onto its published head, and the two
# branches ended at the identical sha with neither able to land. Left to run, the
# waiter wins the lease over an unmoved `main`, the in-hold re-confirmation asks
# only whether `main` moved, and the `/fast-forward` lands the other branch's
# unmerged commits.
#
# So pending is now a POSITIVE claim rather than the absence of the other two: a
# bet is live only while the branch the lease names NOW is somebody else's and
# still carries the base. Everything else is stale — the lease freed, the lease
# passed on, the lease won by us, the lease unreadable.
spec_base=
spec_undo=

# THE BOUNDARY, PUBLISHED TO THE CHILD (CLOUD-748). `verify` runs `claim-race-check`,
# which reads `claimed-keys`, which cannot otherwise tell a commit this branch
# authored from one this speculation adopted — so it reported the waiter as racing
# the very PR the bet was placed on, twice in one session. These are shell
# variables in this process; a child inherits only what is exported. Called at
# every point the bet is placed or cleared, so the two can never disagree.
publish_speculation() {
	if [[ -n "$spec_base" ]]; then
		export BATTEN_SPEC_BASE="$spec_base"
	else
		unset BATTEN_SPEC_BASE
	fi
}
spec_main=
# THE CONFLICT THE PROBE ALREADY COMPUTED (CLOUD-369). `speculate` learns, for
# free, whether the holder's base applies to this branch — and until now that
# answer suppressed only the SPECULATION while the reservation below ran anyway.
# A successor whose base is known to conflict is guaranteed to be voided: its run
# grades a head the fast-forward will refuse, and the rebase that follows still
# has to resolve the same conflict. Measured 2026-08-13 for one such admission:
# a full CI run burned, a ~200s `verify` discarded, a hand-resolved conflict, and
# a second run required. So the answer is kept rather than discarded.
spec_conflicts=0
# Set once the bet has been PUSHED. An unwind then owes the remote a correction
# too: without one, a `die` or a spent lap budget leaves origin holding another
# branch's commits under an open PR, which is the measured two-PRs-at-one-sha
# state.
spec_pushed=0
spec_ref=refs/batten-spec/base
# A SECOND ref, deliberately. The bet's base and the tip it is checked against are
# two different commits, and reusing `$spec_ref` would overwrite the base while
# answering a question about it.
spec_live_ref=refs/batten-spec/live
# CLOUD-862. Set when this process ADOPTED a bet it did not place, which is the
# case `spec_undo` cannot serve: that variable is the pre-bet HEAD and it died
# with the process that placed it. An adopted bet unwinds by replaying onto
# `origin/main` from the base instead, which needs only the base — the repair
# that recovered this branch by hand was exactly `rebase --onto origin/main
# <base>`, and it never consulted an undo point.
spec_recovered=0

# `$spec_ref` EXISTING MEANS A BET IS LIVE, and that is the property CLOUD-862
# adds. It did not hold before: the ref is a fetch destination written before the
# bet is decided (`speculate` below), so it equally marked a candidate fetched
# and declined, a bet already settled, and a bet in flight. A later `land` could
# read it and learn nothing.
#
# Making it mean one thing costs one call on every path that leaves without a
# live bet. Deliberately NOT a second ref beside it: the state was never missing,
# only unreadable, and a sibling ref would be two authorities on one fact.
forget_bet() {
	git update-ref -d "$spec_ref" 2>/dev/null || true
	spec_base=
	spec_undo=
	spec_main=
	spec_recovered=0
}

# Adopt a bet this process did not place. Runs before `settle_speculation`'s own
# logic, so the settle that follows is the ordinary one — there is no second
# settle path to keep in agreement with the first.
#
# The ancestry pair is the whole predicate, and both halves are load-bearing:
# the base must be an ancestor of HEAD (this tree really is linearized on it,
# rather than the ref being left over from a clone that reset) and must NOT be
# an ancestor of `origin/main` (it has not landed, so the bet is still open).
# A ref failing either test is stale and is dropped rather than acted on.
recover_speculation() {
	local recovered
	[[ -z "$spec_base" ]] || return 0
	recovered=$(git rev-parse --verify -q "$spec_ref" 2>/dev/null) || return 0
	# DELIBERATELY NOT deciding "did it land" here. `settle_speculation`'s first
	# arm already answers that, and answers it out loud; an arm here would be a
	# second place deciding one thing, and the one that stayed silent — which is
	# how this whole class went unnoticed. Adopt, then let the ordinary settle
	# run. The only judgement this function makes is whether the ref describes
	# THIS tree at all.
	if ! git merge-base --is-ancestor "$recovered" HEAD 2>/dev/null; then
		# The ref names a commit this tree is not built on, so whatever it was
		# recording is not true of this HEAD.
		forget_bet
		return 0
	fi
	spec_base="$recovered"
	spec_recovered=1
	publish_speculation
	echo "land: adopting an unsettled speculation on $(git rev-parse --short "$recovered") left by an earlier run; settling it before anything is pushed"
}

# THREE OUTCOMES, NOT TWO, and conflating the middle one with the last is the
# defect worth naming: a bet is usually still PENDING at the next lap. The holder
# takes minutes to land, so "not on main yet" is the normal reading, and
# unwinding on it would undo the linearization every single lap and leave the
# mechanism running while achieving nothing — warm, then cold, then warm again.
#
#   won      the base is an ancestor of `origin/main`; the holder landed
#   pending  `origin/main` has not moved since the bet; nothing has been decided
#   lost     `main` moved and took something else; the bet cannot come true
#
# IS THE BET STILL LIVE? Asked of the lease as it reads NOW, not of the lease as
# it read when the bet was placed. Fails closed everywhere: an unreadable lease,
# an unfetchable branch and an unknown ancestry are all "stale", because failing
# open here would make a network blip the thing that lands somebody else's work.
bet_is_live() {
	local now
	now=$(mise run land-lock peek branch 2>/dev/null || true)
	# Nobody holds it, or WE do. Holding the lease with the base not yet on
	# `main` can only mean the branch we bet on is gone: a base that actually
	# landed is caught one arm earlier, by the ancestry check against
	# `origin/main`. So this costs a warm tree in no case that was going to win.
	[[ -n "$now" ]] || return 1
	[[ "$now" != "$branch" ]] || return 1
	git fetch -q origin "+refs/heads/$now:$spec_live_ref" 2>/dev/null || return 1
	# The holder may have changed, or force-pushed past our base. Either way the
	# question is the same one: is the commit we bet on still on the branch that
	# is about to become `main`. Asked of the REF rather than a sha resolved from
	# it, so a ref the fetch did not actually write is a non-zero exit here rather
	# than a resolve step that has to remember to fail closed.
	git merge-base --is-ancestor "$spec_base" "$spec_live_ref" 2>/dev/null
}

# Drop the borrowed range, and correct the remote if the bet was published. The
# lap's ordinary rebase onto `origin/main` runs immediately after this returns,
# so there is nothing to re-linearize by hand — and `speculate` re-bets on
# whoever holds the lease now, which is the "rewind onto the next holder" half.
unwind_speculation() {
	# TWO UNWINDS, because an adopted bet has no undo point (CLOUD-862). The
	# reset is exact and stays the path whenever this process placed the bet.
	# The replay is for a bet inherited from a dead run: it needs only the base,
	# and it is what recovered this branch by hand — `origin/main..HEAD` minus
	# the borrowed range is precisely this branch's own commits.
	if [[ -n "$spec_undo" ]]; then
		echo "land: $1; unwinding to $(git rev-parse --short "$spec_undo") rather than carrying another branch's commits"
		git reset -q --hard "$spec_undo" || die "could not unwind the speculative rebase; the tree is not somewhere this loop can push from."
	else
		echo "land: $1; replaying this branch's own commits onto $(git rev-parse --short origin/main) rather than carrying another branch's"
		git rebase --onto origin/main "$spec_base" >/dev/null 2>&1 || {
			git rebase --abort 2>/dev/null || true
			die "could not replay off the adopted speculation base $(git rev-parse --short "$spec_base"); the tree carries another branch's commits and this loop must not push it."
		}
	fi
	if [[ "$spec_pushed" = 1 ]]; then
		# Re-draft BEFORE moving the ref, the same ordering the red path uses:
		# the corrective push emits a `synchronize`, and a ready PR would spend a
		# matrix on it. The next lap readies again when it has something worth
		# confirming.
		redraft "its published head carried a base that is not landing, so the branch is being rewound"
		git push --force-with-lease -u origin "$branch" >/dev/null 2>&1 ||
			echo "land: could not rewind the published branch; it still carries commits that are not landing"
		spec_pushed=0
		# The run in flight graded a head this branch no longer has, so the
		# successor's ready/push pair is owed again for the new one.
		admitted_sha=
	fi
	forget_bet
	publish_speculation
}

settle_speculation() {
	# ASK GIT BEFORE ASKING THE PROCESS (CLOUD-862). This used to open on
	# `[ -n "$spec_base" ] || return 0`, so a `land` that had not placed the bet
	# itself returned on the first line — while the ref holding the answer sat
	# on disk beside it. Measured: a stopped `land` left seven of another
	# branch's commits in the tree, and the next one ran a full clean `verify`
	# and reached the push with them.
	recover_speculation
	[[ -n "$spec_base" ]] || return 0
	if git merge-base --is-ancestor "$spec_base" origin/main 2>/dev/null; then
		echo "land: the speculation landed — already linearized on $(git rev-parse --short origin/main), no rebase needed"
		forget_bet
		spec_pushed=0
		publish_speculation
		return 0
	fi
	# An ADOPTED bet has no `spec_main` to compare against — the process that
	# recorded it is gone — so the "has main moved" arm cannot judge it. The
	# lease can: `bet_is_live` reads who holds it NOW and whether the base is
	# still on the branch about to land, which is the question either way.
	if [[ "$spec_recovered" = 1 ]]; then
		if bet_is_live; then
			return 0
		fi
		unwind_speculation "an earlier run bet on a base that is no longer landing"
		return 0
	fi
	if [[ "$(git rev-parse origin/main)" = "$spec_main" ]]; then
		# `main` has not moved, which used to end the question. It does not: the
		# holder can go away without `main` moving at all, and that reading is
		# indistinguishable from "still landing" unless the lease is re-read.
		if bet_is_live; then
			# Undecided. Keep the tree: the holder is still landing, and this
			# branch is already linearized behind it.
			return 0
		fi
		unwind_speculation "the branch this speculation bet on is no longer the base that is about to land"
		return 0
	fi
	# The bet lost: the holder did not land, or `main` took something else. Undo
	# it rather than trying to salvage it — our own commits are all that
	# `spec_undo` holds, and the lap's ordinary rebase onto `origin/main` is
	# about to run anyway.
	unwind_speculation "the speculation did not land"
}

# Rebase onto the head the lease says is about to become `main`. Every failure
# here is a FALLBACK, never a stop: the holder may never land, so a conflict
# against its head is information about a base that may not happen, not the
# `die`-worthy conflict the real rebase onto `origin/main` reports.
speculate() {
	local base head_ref
	head_ref="$1"
	[[ -n "$head_ref" ]] || return 0
	# Fetch the holder's branch into a ref of our own rather than reading
	# FETCH_HEAD, which is one file per clone and therefore racy the moment
	# anything else in this process fetches (`land-lock`'s own read path carries
	# the same fix, for the same reason).
	git fetch -q origin "+refs/heads/$head_ref:$spec_ref" 2>/dev/null || {
		echo "land: cannot fetch $head_ref to speculate on; staying linearized on main"
		return 0
	}
	base=$(git rev-parse "$spec_ref" 2>/dev/null) || {
		git update-ref -d "$spec_ref" 2>/dev/null || true
		return 0
	}
	# ONE OUTSTANDING BET AT A TIME. A waiter laps repeatedly while the same
	# holder lands, and re-betting on each lap would overwrite `spec_undo` with a
	# HEAD that is itself speculative — so unwinding would restore a tree that
	# still carried somebody else's commits, which is the exact hazard the undo
	# exists to remove. It would also re-mint a sha every lap and throw away a
	# verify receipt for no gain, since the base has not changed.
	[[ "$spec_base" != "$base" ]] || return 0
	# Already a descendant — nothing to speculate, and rebasing would be a no-op
	# that still mints a new sha and throws away this HEAD's verify receipt.
	# The ref goes with it (CLOUD-862): the fetch wrote it before this branch was
	# taken, and leaving it behind is what made its existence mean nothing.
	if git merge-base --is-ancestor "$base" HEAD; then
		git update-ref -d "$spec_ref" 2>/dev/null || true
		return 0
	fi
	# Only ever our own last NON-speculative HEAD. Settling clears it, so a bet
	# placed after a settled one records the right undo point.
	[[ -n "$spec_undo" ]] || spec_undo=$(git rev-parse HEAD)
	if ! git rebase "$base" >/dev/null 2>&1; then
		git rebase --abort 2>/dev/null || true
		git reset -q --hard "$spec_undo" 2>/dev/null || true
		spec_undo=
		# No bet was placed, so the ref must not claim one (CLOUD-862).
		git update-ref -d "$spec_ref" 2>/dev/null || true
		# A conflict discovered here is the whole point of doing this early: it
		# is free now and expensive later. Reported, not resolved — resolving
		# another branch's conflict before it has landed would be resolving it
		# against a base that may never exist.
		spec_conflicts=1
		echo "land: $head_ref conflicts with this branch; not speculating on it (the conflict is real and arrives when it lands)"
		return 0
	fi
	spec_conflicts=0
	spec_base="$base"
	# The `main` this bet was placed against. Without it "not landed yet" and
	# "landed something else" are the same reading, and the bet would be unwound
	# every lap while the holder was still perfectly on course.
	spec_main=$(git rev-parse origin/main)
	publish_speculation
	echo "land: speculatively linearized onto $head_ref@$(git rev-parse --short "$base") — the main that is about to exist"
}

# --- say what this land is doing, so nobody has to read its log (CLOUD-425) ---
#
# `land` is backgrounded by contract, and a backgrounded task's death used to be
# observable only as a harness notification that does not survive a container
# restart. Pushing the phase at transitions this loop ALREADY has means the
# answer is readable — by `mise run alive` — without cooperation from a process
# blocked in a 200s gate, and without anyone grepping this task's log.
#
# Every call is best-effort: a land must never fail because its own bookkeeping
# could not be written. The registry degrades to silence; it never lies.
note_phase() {
	mise run task-registry phase "$$" "$1" >/dev/null 2>&1 || true
}
# Nested gates report against THIS task's entry rather than minting one per
# subprocess: `step-receipt check` reads it to name the step `verify` is on, so
# a land blocked in a 200s `cargo test` says `test:cargo` rather than `verify`.
export BATTEN_TASK_PID=$$

# --- one land per clone (CLOUD-428) ------------------------------------------
#
# The landing lease cannot answer this: it is re-entrant per clone by design, so
# two `land` processes in one checkout both acquire and the second heartbeat
# renews the first's lease. Measured 2026-08-12 — three concurrent lands on one
# branch, rebasing and pushing against each other for ~30 minutes.
#
# `singleton_held` is why the release is conditional: a REFUSED land must run
# its EXIT trap without deleting the lock the live one holds. Same discipline as
# `target-ensure`'s `held` flag, for the same reason.
singleton_held=no

# CLOUD-458. Readying is how this task says "a landing is in progress"; nothing
# said the opposite when it stopped. Only the RED path re-drafted, so a landing
# interrupted any other way — a lost lease, a rebase conflict, a stopped task —
# left the PR ready for good, and every later push to it bought a full matrix
# with no landing attempt in progress at all. Measured 2026-08-12: four
# concurrent `pull_request` matrices, three of the four PRs `draft=false` behind
# an interrupted land.
landed=no

# CONDITIONAL ON THE VERDICT, which is the design rather than a caveat. The
# pre-push ready fires only on a head with NO graded run, so re-drafting a head
# that already graded green strands it: unmergeable while draft, and unreadyable
# because `graded_runs` is no longer zero. Readying it anyway is the worse
# repair — `ready_for_review` is a CI trigger, so recovering a green head would
# buy a whole matrix, where today that resume is a free fast-forward.
#
# `checks-green` is the authority for "is this head green", NOT `graded_runs`:
# the two answer different questions, and the one that counts a failed or
# cancelled run as an answer would leave a green head ready only by accident.
close_the_tap() {
	[[ "$landed" = no ]] || return 0
	# A land that never took the singleton owns neither the lease nor the PR —
	# the discipline `singleton_held` already enforces for the release, and the
	# reason a REFUSED second land must not touch the live one's work.
	[[ "$singleton_held" = yes ]] || return 0
	[[ -n "${pr:-}" ]] || return 0
	# Only the draft state is asked for, in the same call shape the ready block
	# uses. Whether the PR is still OPEN is already answered: a merge sets
	# `landed`, and a PR closed without merging has died above — re-drafting one
	# would fail, which `redraft` swallows. Asking anyway would cost a `pr view
	# --json state`, and that call is sequenced by the poll it belongs to.
	local rc=0
	[[ "$(gh pr view "$pr" --json isDraft --jq .isDraft 2>/dev/null)" = "false" ]] || return 0
	mise run checks-green >/dev/null 2>&1 || rc=$?
	# 0 green: leave it ready, since the resume costs nothing. 2 could not look:
	# never strand a head on a reading we failed to take. 1 red and 3 no-answer
	# both mean the resume needs a fresh run whatever happens, so the draft
	# costs nothing and stops every push until one starts.
	case "$rc" in
	1 | 3) ;;
	*) return 0 ;;
	esac
	redraft "the landing stopped without merging, so no later push spends a runner until one starts again"
}

on_exit() {
	# Before the lease drop: the tap is what another session's spend depends on,
	# and a failure here must not stop the rest of the trap. `redraft` already
	# swallows its own failure, which is the required posture — an exit path
	# that can fail on cleanup is worse than the leak it closes.
	close_the_tap || true
	drop_lease
	# WHY THIS STOPPED, when what stopped it was not this process (CLOUD-499).
	# The lease heartbeat kills a landing that has stopped progressing, and a
	# stop with no stated reason reaches the agent as "verify and CI disagree" —
	# CLOUD-470's failure, reintroduced by the fix for a different one. Read and
	# removed here so it can never be reported twice or outlive its landing.
	bail_reason="$(git rev-parse --git-dir 2>/dev/null)/batten-land-lock/bail-reason"
	if [[ -s "$bail_reason" ]]; then
		echo "land: $(cat "$bail_reason")" >&2
		rm -f "$bail_reason" 2>/dev/null || true
	fi
	if [[ "$singleton_held" = yes ]]; then
		mise run singleton release land >/dev/null 2>&1 || true
	fi
	# A SIGKILLed land cannot run this, which is exactly the case `alive` reports
	# as crashed rather than as absent — the distinction that cost seventeen
	# minutes of guessing on 2026-08-12.
	mise run task-registry unregister "$$" >/dev/null 2>&1 || true
}
trap on_exit EXIT
trap 'exit 1' INT TERM

# Before anything else: a second land must spend no CI, take no lease and move
# no ref. The refusal names the live pid and its phase, so the answer to "then
# what is running?" comes with the refusal rather than needing a hunt.
# A `die`, not a bare `exit`, so `tests/land.bats`'s stop counter sees it: an
# exit nothing counts is an exit nothing tests, and that assertion exists
# precisely to stop a new stopping condition being added silently. The pid and
# phase come from `singleton`'s own refusal on the line above.
if ! mise run singleton acquire land "$$"; then
	die "refusing to start a second land in this clone — the live one is named above."
fi
singleton_held=yes

# Registered only past the refusal, so a refused run leaves no entry claiming it
# is running.
mise run task-registry register land "$$" starting >/dev/null 2>&1 || true

# "Does this SHA carry an answer yet?" — the conclusions `checks-green` grades,
# over the checks it requires, so the two agree by construction on what counts as
# one. Both read $CI_REQUIRED_CHECKS from mise.toml [env]; a second copy that
# drifted would put this task back to waiting on runs that will never be graded.
#
# The CONCLUSION list has to mirror it just as exactly, and CLOUD-363 is what a
# drift there costs. `cancelled` counted as graded here while `checks-green` read
# it as red, and the two composed into a trap with no exit: the red stopped the
# lap, and "already graded" then suppressed the ready that would have replaced
# the cancelled runs, so every later lap re-read the identical stale set. A
# cancelled run is not an answer at either end now, which is what makes the next
# lap re-fire the ready and buy a real run. `neutral` is here for the mirror-image
# reason: `checks-green` grades it, so omitting it would leave a green SHA reading
# as unanswered and buy a second run for a head that already has its verdict.
# Absent from the remote, or unreachable, reads as 0: a SHA with no runs is
# exactly the one that needs the event, and the caller's other guards decide
# whether to spend it.
#
# Scoped to the required set for the reason CLOUD-327 records: `SonarCloud Code
# Analysis` and `release-plz` are not draft-gated, so they grade on the draft
# push. Counting them made this read "answered" on a head whose own checks were
# all draft-era skips, so the ready was never re-fired and the skips were never
# replaced — the #182/#177 shape, reached from the other direction.
# CANCEL WHAT IS ALREADY VOID (CLOUD-369, and CLOUD-240 is what permits it).
# When `main-watch` wins the CI race the run in flight cannot land — its verdict
# is void by construction, which is why the lap ends. But the run keeps BILLING
# until something supersedes it, and the only thing that does is the next push's
# `concurrency: cancel-in-progress`. Since the lease budgets were re-priced
# (CLOUD-399) that next push can be many whole lease waits away, so a doomed
# four-job matrix bills for minutes to produce an answer nobody will read.
#
# CLOUD-240 refused hand-cancelling and its wording is the licence here:
# "supersede your own runs, never someone else's", and "cancelling another ref's
# runs would reverse" that. This reaches runs for THIS lap's head sha and nothing
# else — a sha no other branch has, so the blast radius is one push's worth of
# runs by construction rather than by filtering.
#
# Best-effort throughout: a cancellation that fails costs the minutes it would
# have saved and changes no verdict, so nothing here is guarded into a stop. The
# lap is already over.
cancel_own_run() {
	local id
	for id in $(gh api "repos/{owner}/{repo}/actions/runs?head_sha=$1&per_page=30" \
		--jq '.workflow_runs[]? | select(.status != "completed") | .id' 2>/dev/null); do
		gh api -X POST "repos/{owner}/{repo}/actions/runs/$id/cancel" >/dev/null 2>&1 &&
			echo "land: cancelled run $id on ${1:0:8} — void the moment main moved, and a void run still bills"
	done
}

# A run CI DECLINED is not a run that failed (CLOUD-470). `ci-lease-precondition`
# stops an unauthorised head by CANCELLING the run it stands in, and `final` reds
# under `always()` because its `needs:` assertion fails — so the wait comes back
# non-zero with nothing about this branch broken. The generic red message then
# tells the agent that verify and CI disagree and to fix the mismatch locally,
# which names the one cause that is not true and points away from the remedy.
#
# Measured on the population that cannot afford a wrong instruction: 11 of 13 open
# PRs carried a `land` predating the lease, so every one of those agents, on
# restart, hits a cancelled run and is sent to debug a disagreement that does not
# exist. The runner already writes the right answer as an annotation; this is the
# same answer carried back through the channel `land` actually speaks on.
#
# IT CALLS `land-lock authorises` OR IT IS WRONG. The first cut of this read the
# run list for a raw `conclusion == "cancelled"`, which is a SECOND PREDICATE for
# "this run was declined" — and two authorities for one fact is the CLOUD-351
# shape, where only the newer one decides. `authorises` is what the runner itself
# consults, so asking it here is asking the same question of the same oracle,
# locally, on a path that is already stopping. It costs nothing on the hot loop.
#
# Its contract: 0 run / 3 stop / 2 could not look, fail-open everywhere it cannot
# tell. Exit 3 is the declination, and it FAILS OPEN to the red message on
# anything else — the asymmetry is deliberate, because a wrong "nothing is broken"
# costs a landing while a wrong "go debug this" costs a session.
#
# WHAT THIS DELIBERATELY DOES NOT ANSWER, recorded rather than papered over.
# `authorises` takes a BRANCH and answers about the lease as it is NOW: it has no
# run id, no SHA and no history, so it cannot literally answer "was this concluded
# run declined". That is sound for the population CLOUD-470 names — a stale agent
# takes no lease, so when it reads red the lease authorises someone else and this
# returns 3 — and for a current `land`, which holds its own lease and gets today's
# message. What is genuinely lost is a `cancel-in-progress` cancellation, which
# the raw read also caught; that is a superseded run, not a declined one, and the
# lap that superseded it is the thing to look at.
declined_by_lease() {
	local rc=0
	mise run land-lock authorises "$1" >/dev/null 2>&1 || rc=$?
	[[ "$rc" = 3 ]]
}

# THE THIRD THING THAT ARRIVES AT THE RED STOP (CLOUD-483). A job that died in the
# setup action that installs our toolchain reds the branch and answers nothing:
# measured five times on CLOUD-404, twice with different curl codes, and every
# time `land` sent the agent to reproduce a failure that passes locally. The remedy it named cost a
# whole matrix; `gh run rerun --failed` costs one job, measured on #376.
#
# IT CALLS `nonverdict-scan` OR IT IS WRONG, for the reason the arm above states.
# That task owns the classification — a failed job reached a verdict iff one of
# its failed steps is named `Run mise run <task>` — and it is a CLOSED predicate
# resting on the invariant `ci-local-parity` gates, not an allowlist of setup
# steps that goes stale the first time a workflow gains one. A copy of that jq
# here would be a second authority over the same fact (CLOUD-351).
#
# EMPTY IS NOT UNANIMOUS, and this is the whole hazard. Zero records satisfies
# "every record is a nonverdict" vacuously, and a branch that is genuinely red
# would then be re-run until the budget ran out. Zero records is what an
# unreadable payload, a roster miss, or a failure confined to the `final` fan-in
# all produce — so it is the "could not look" case and falls through to the red
# message, the same order `checks-green` uses when it tests no-answer before red.
transient_runs=
absorbed_transient() {
	local sha="$1" runs run one records=""
	transient_runs=

	# No `per_page` here, deliberately: `tests/land.bats`'s keyed-verdict sensor
	# asserts this file carries no windowed page size, because the fast-forward
	# verdict must be found by its key rather than by a window. This query is a
	# different endpoint entirely, and it needs no page size — a head SHA's failed
	# runs are a handful — so the sensor stays exact instead of being spelled past.
	runs=$(gh api "repos/{owner}/{repo}/actions/runs?head_sha=$sha&status=failure" \
		--jq '.workflow_runs[]?.id' 2>/dev/null) || return 1
	[[ -n "${runs//[[:space:]]/}" ]] || return 1

	while IFS= read -r run; do
		[[ -n "$run" ]] || continue
		one=$(mise run nonverdict-scan --run "$run" 2>/dev/null) || return 1
		records="${records}${one}"$'\n'
	done <<<"$runs"

	[[ -n "${records//[[:space:]]/}" ]] || return 1
	! grep -q '^verdict' <<<"$records" || return 1

	transient_runs="$runs"
	# A here-string, not a pipe: `pipefail-grep-check` refuses a producer piped
	# into an early-exiting grep, and is right to — under `pipefail` that shape is
	# how a MATCH comes to report failure. The same rule caught the same mistake
	# in `finding-sink-check` this morning.
	grep '^nonverdict' <<<"$records" || true
	return 0
}

# Re-run the failed jobs, refund the lap, and charge the count. The pointer is not
# decoration: an absorbed transient with no durable trace is how the last one was
# diagnosed correctly and then lost, so every occurrence stays attachable to
# CLOUD-404.
charge_transient() {
	local run
	for run in $transient_runs; do
		gh run rerun "$run" --failed >/dev/null 2>&1 ||
			die "CI on ${sha:0:8} failed before any \`mise run\` step — a provisioning transient, not a verdict — but re-running run $run was refused. Do: gh run rerun $run --failed, then mise run land"
		echo "land: lap $lap — run $run failed before reaching a verdict; re-ran its failed jobs (CLOUD-404). Not a verdict on this branch."
	done
	lap=$((lap - 1))
	transients=$((transients + 1))
	[[ "$transients" -le "$max_transients" ]] ||
		die "CI failed before reaching a verdict $max_transients times running on ${sha:0:8}. That is not a flake any more — the provisioning path is broken and re-running it again would spend jobs to learn the same thing. Do: look at the failing step, then mise run land"
}

graded_runs() {
	local n
	# The roster is guarded at TOP LEVEL, not here — see the check beside the
	# other preconditions. A `die` in this function would run inside the `$( )`
	# its callers wrap it in, so it would exit the SUBSHELL and the lap would
	# carry on with an empty reading (CLOUD-467).
	#
	# The `|| n=0` below is KEPT for what it was written for: a transient `gh` or
	# `awk` failure answering "ungraded" is the choice that makes progress, and
	# stopping the loop on it would be worse.
	n=$(gh api "repos/{owner}/{repo}/commits/$1/check-runs" \
		--jq '.check_runs[]? | "\(.conclusion // "-")\t\(.name)\t\(.started_at // "")\t\(.id // 0)"' 2>/dev/null |
		awk -F'\t' -v req="${CI_REQUIRED_CHECKS:?}" -v answered="${CI_ANSWERED_CONCLUSIONS:?}" '
			BEGIN {
				n = split(req, roster, ","); for (i = 1; i <= n; i++) want[roster[i]] = 1
				# ONE DECLARED SET, read by `checks-green` too (CLOUD-376). The
				# two ends kept a hand-maintained list each, in agreement only by
				# a paragraph of comment — and that is exactly the guarantee that
				# had already failed: `neutral` was missing from this side until
				# #302 added it, and nothing detected the gap.
				m = split(answered, concls, ","); for (i = 1; i <= m; i++) isanswer[concls[i]] = 1
			}
			!($2 in want) { next }
			{
				# The same latest-per-name rule `checks-green` judges by, over
				# the same roster (CLOUD-436). A draft-created head keeps its
				# skip set forever, and counting a superseded run would report
				# an answer this head does not have — leaving the ready that
				# starts CI unfired.
				key = $3 "|" sprintf("%020d", $4 + 0)
				# Not-an-answer ranks ABOVE an answer on an equal key, so an
				# unorderable pair falls to "no verdict" rather than to one.
				# `cancelled` lands here by its absence from the declared set, so
				# the two ends cannot disagree the way CLOUD-363 did.
				rank = (!($1 in isanswer)) ? 2 : 1
				if (!($2 in bestkey) || key > bestkey[$2] ||
					(key == bestkey[$2] && rank > bestrank[$2])) {
					bestkey[$2] = key
					bestrank[$2] = rank
					bestconcl[$2] = $1
				}
			}
			END {
				for (i = 1; i <= n; i++) {
					if (bestconcl[roster[i]] in isanswer) hit++
				}
				print hit + 0
			}
		') || n=0
	echo "${n:-0}"
}

# `set -m` gives each background job its own process group, so `kill -- -PID`
# reaches the whole tree (mise -> the task -> gh/sleep). Without it the loser of
# the race is orphaned and keeps polling for the rest of the session.
set -m

[[ "$branch" != "main" ]] || die "refusing to land from main — work happens on a short-lived branch."

# --- the webhook subscription this repo's contract forbids (CLOUD-518) --------
#
# AGENTS.md bans PR-webhook babysitting twice over — this loop runs on "no
# timeout, no cap, **never the PR webhook**", and no heartbeat may babysit a PR —
# and the harness arms a subscription on every PR this repo opens anyway. Measured
# on #397, #402 and #489, and on two of those with no `subscribe_pr_activity` call
# behind it, which is why a deny rule on the tool closes only the path nobody
# used. The remedy was an agent remembering, which is prose and therefore
# feedforward only.
#
# THE DROP HAPPENS HERE NOW (CLOUD-790). This block used to say the tool was
# unreachable from a task, because a POST to the session's MCP endpoint answered
# `401` (CLOUD-673) — and that 401 was a missing `Authorization` header, not a
# missing credential. Re-measured 2026-08-20: with the container's own
# session-ingress token as a bearer, `POST /v2/ccr-sessions/<id>/github/mcp`
# answers 200 and serves `unsubscribe_pr_activity`. The toolbox route stays shut
# to this principal (403), which is why `drop` takes the github one.
#
# That matters because the agent-side call could never be made silent: the
# connector sets the verb to `always_ask`, and CLOUD-765 measured that a hook
# returning `allow` does not skip that prompt. So the previous shape charged a
# human one approval click per landing, while the harness ARMED the subscription
# with no click and no tool call at all. `drop` closes that asymmetry.
#
# `drop` FAILS OPEN and `check` is unchanged, which is what keeps this safe on the
# critical path: where the call cannot be made — off harness, no token, any
# non-200 — nothing is minted, `check` refuses exactly as before, and the agent's
# manual `record` is still the way through. The pair sits before the singleton and
# the lease, so a refusal still costs nothing at all.
#
# The gate's own words reach the operator (CLOUD-407): it names the command that
# mints the receipt, so this `die` adds only the landing's context.
# THE SCRIPT MUST CARRY NO `|`, and this line is why the rule exists: the
# declaration grammar is three pipe-separated fields, so the `|| true` below —
# matched literally by the obvious sed — was parsed as a fourth field and
# truncated, and `mutant` reported `unterminated s command`. `pr-unsubscribed`
# records the same trap against its own rows. Matching on the prefix and `.*`
# keeps the script pipe-free while still naming exactly one line.
#MUTANT subscription-undropped|s@^mise run pr-unsubscribed drop.*@true@|the landing makes the unsubscribe call itself
mise run pr-unsubscribed drop "$pr" || true
#MUTANT subscription-unenforced|s/^if ! mise run pr-unsubscribed check "\$pr"; then$/if false; then/|a session that has not dropped the subscription cannot land
if ! mise run pr-unsubscribed check "$pr"; then
	die "#$pr's webhook subscription has not been dropped, and the refusal above says how. Nothing has been spent — do that, then run land again."
fi

lap=0
lease_waits=0
answer_unknowns=0
# Absorbed provisioning transients, counted across the whole invocation rather
# than reset per lap: three in one landing is the broken-world signal, whether or
# not a good lap happened in between (CLOUD-483).
transients=0
# Set by `rate_limit_pause` so the exhaustion message can state the reset time the
# code already had, instead of telling the human to go run `gh api rate_limit`.
rate_reset_note=""
# Whether this pass holds the lease, or is running as the admitted successor.
have_lease=1
# Sticky across laps: the reservation is held until the lease turns over, so
# re-reserving each lap would rewrite the ref to say what it already says.
admitted=0
# The HEAD this branch last pushed as the admitted successor. A speculation that
# moves HEAD makes it stale, and a stale one means the run in flight grades a
# commit this branch no longer has — so the pair runs again for the new head.
admitted_sha=
while :; do
	lap=$((lap + 1))
	# THE REMEDY NAMES THE CONTINUING ACTION, and that is not stylistic. This
	# message used to end "Look before lapping again", which reads as STOP — and
	# an agent stopped, for 55 minutes, on a one-commit branch. Stopping is the
	# single worst move available here: this header's own opening paragraph says
	# lapping is the catch-up mechanism, so a branch that stops ages while the
	# target keeps moving, which is the "cannot land at all" state the design
	# exists to prevent. A cap is a checkpoint, never a stop sign; the imperative
	# has to say so, and it has to name the check rather than ask for judgement.
	[[ "$lap" -le "$max_laps" ]] ||
		die_with "$LAND_EXIT_RUNAWAY" \
			"still not linear after $max_laps laps, each of which bought a CI matrix; \`main\` is moving faster than a lap takes. Check the current rate with \`git log --oneline --since=30.minutes origin/main | wc -l\`, then RUN THIS AGAIN — lapping is how a branch catches up, and stopping is how it stops being landable."

	# A lap holds the lease only across its own CI window. Dropping it here — at
	# the top, covering every `continue` below uniformly — means a lap that lost
	# re-queues behind whoever is landing now instead of holding the fleet
	# through its own rebase and re-verify. Idempotent, so the laps that never
	# acquired pay nothing.
	drop_lease

	# --- be a direct descendant of origin/main, or stop for the one decision ---
	note_phase "rebase(lap $lap)"
	fetch_main
	# Settle any bet from the previous lap FIRST, and before anything below can
	# push. A won bet leaves this branch already linearized on the new `main`
	# with its verify receipt intact — which is the entire saving. A lost one is
	# unwound here, where it costs a reset, rather than discovered at the push.
	settle_speculation
	if ! git merge-base --is-ancestor origin/main HEAD; then
		echo "land: lap $lap — rebasing onto $(git rev-parse --short origin/main)"
		if ! git rebase origin/main; then
			git rebase --abort 2>/dev/null
			die "rebase onto origin/main conflicts. This is the one step the loop cannot do for you — resolve it and run land again. Lapping often is what keeps this small."
		fi
	fi
	# The `main` this lap is built against, captured once. The lease wait below
	# can take a full TTL, and this is what the winner compares against before it
	# spends a matrix (CLOUD-369).
	lap_main="$(git rev-parse origin/main)"

	# --- prove the tree, unless this exact commit already carries the proof ---
	#
	# `verified` reads the receipt keyed to this exact HEAD, which also carries
	# the `origin/main` it was linear against — so an amend, a rebase, or a main
	# that moved all invalidate it. When it still holds, nothing has changed and
	# re-running `verify` would spend minutes reaching a known answer.
	#
	# Asked as a QUESTION, so its output is dropped: `verified` is a gate, and a
	# gate answering "no receipt" says so with an `::error::`. Here a no is the
	# ordinary answer — the commit was just made — and printing it on every
	# successful landing is how `::error::` stops meaning anything. The same call
	# below is a GUARD, where a no really is the failure, and it keeps its voice.
	note_phase "verify(lap $lap)"
	if mise run verified >/dev/null 2>&1; then
		echo "land: lap $lap — HEAD already carries a verify receipt; not re-proving it"
	else
		# A non-zero `verify` is not one answer (CLOUD-318). `verify` runs for
		# ~150s, and on a busy `main` that is long enough for the tip to move
		# past the one this lap rebased onto — so `linear-check` measures
		# against a newer main and refuses. Nothing is wrong with the branch and
		# there is nothing to reproduce: the next lap's rebase fixes it by
		# construction, which is the same race the wait phase below already
		# treats as a lap. Exit 2 is that verdict and only that verdict; every
		# other non-zero is content, and content still stops on lap 1 with the
		# message unchanged. Measured on #240: run 1 died here, run 2 landed
		# after three laps with zero edits.
		# --- CLOUD-423: verify races main-watch, the same pair as the CI wait ---
		#
		# verify used to run blind: only its last step discovered main had moved,
		# ~220s after the fact, and ~45% of laps paid the full gate to learn what
		# a 1s conditional poll knew (CLOUD-392 measured the steady state:
		# survival ≈ e^(-220/363) per lap). The abort is safe by construction —
		# verify writes its receipt only after its guarded steps
		# (tests/task-fail-closed.bats pins it), so a killed verify leaves no
		# receipt and the next lap re-proves, cheaply, from the per-step receipts
		# (CLOUD-424). Named pids and post-wait residue reaping, per 0552c41 and
		# CLOUD-434. The interval drops to 1s for this race: a conditional 304
		# costs no rate limit, so the poll's price is the round trip.
		rc_v="$(mktemp)"
		rc_vm="$(mktemp)"
		log_v="$(mktemp)"
		: >"$rc_v"
		: >"$rc_vm"
		: >"$log_v"
		fifo_v="$(new_rendezvous)" ||
			die "could not create the race rendezvous for verify — the lap cannot wait on two answers without it, and guessing which one won is the false green this race exists to avoid."
		(
			# TEED, not redirected (CLOUD-407). The operator still sees verify
			# stream live — a redirect would make a ~170s gate look hung — and the
			# copy is what lets the stop below carry the gate's own `path:line`
			# pointers. They already existed on PR #322, three of them, and the
			# only reason nobody saw them was that this subshell's output scrolled
			# past twenty lines above a message that said "rebase".
			#
			# `${PIPESTATUS[0]}` rather than `$?`, spelled out rather than leaning
			# on `pipefail`: the verdict is verify's, and reading it from the
			# pipeline's aggregate would make a failure of `tee` — a full disk, a
			# vanished tmpdir — indistinguishable from a refused tree.
			mise run verify 2>&1 | tee "$log_v"
			echo "${PIPESTATUS[0]}" >"$rc_v"
			echo v >"$fifo_v"
		) &
		v_pid=$!
		(
			LAND_RACE=verify MAIN_WATCH_INTERVAL="${LAND_VERIFY_WATCH_INTERVAL:-1}" \
				mise run main-watch "$(git rev-parse origin/main)" >/dev/null 2>&1
			echo $? >"$rc_vm"
			echo m >"$fifo_v"
		) &
		vm_pid=$!
		race_pid_a=$v_pid
		race_pid_b=$vm_pid
		await_first "$fifo_v"
		vwinner="$AWAIT_WINNER"
		kill -- -"$v_pid" -"$vm_pid" 2>/dev/null
		wait "$v_pid" "$vm_pid" 2>/dev/null
		reap_residue "$v_pid"
		reap_residue "$vm_pid"
		race_pid_a=
		race_pid_b=
		verify_rc="$(cat "$rc_v" 2>/dev/null)"
		vmain_rc="$(cat "$rc_vm" 2>/dev/null)"
		# CLOUD-510: void the loser. `m` means main-watch reached the rendezvous
		# first, so whatever verify managed to write is about a tree that is no
		# longer the one being landed. The arms below are unchanged and stay the
		# authority on what a code MEANS; this only decides whose code counts.
		case "$vwinner" in
		m) verify_rc="" ;;
		v) vmain_rc="" ;;
		esac
		# The tail is taken BEFORE the temp files go, because `die` exits and a
		# message assembled after the cleanup would name a file that is gone. It
		# is only ever read on the stop path below; a lap that laps pays nothing.
		verify_tail="$(tail -n "${LAND_VERIFY_TAIL_LINES:-40}" "$log_v" 2>/dev/null || true)"
		# CLOUD-861: a full disk is not a verdict about this tree. Grepped over
		# the WHOLE log rather than `$verify_tail`, because the linker writes
		# ENOSPC where it fails and the gate keeps running after it — measured
		# 2026-08-21, the line landed ~40 lines above the tail and the stop below
		# reported a clean-looking test failure instead.
		#
		# `grep -qF` over a literal, never a `df` reading: the question is what
		# THIS run hit, and by the time the stop is composed the space may have
		# been reclaimed by another process. The string is the compiler's, so a
		# reclaim between failure and report cannot erase the evidence.
		verify_enospc=""
		grep -qF 'No space left on device' "$log_v" 2>/dev/null && verify_enospc=1
		rm -f "$rc_v" "$rc_vm" "$log_v"
		if [[ -z "$verify_rc" ]] && [[ "$vmain_rc" = "0" ]]; then
			echo "land: lap $lap — main moved past $(git rev-parse --short origin/main) while verify ran; its receipt would be void, so the rest of the gate is not paid out. Lapping."
			continue
		fi
		if [[ -z "$verify_rc" ]]; then
			# Neither answered: verify died without a verdict and main did not
			# move. Lap rather than guess — the next lap re-proves from the
			# step receipts, so the retry costs seconds.
			echo "land: lap $lap — no verdict from verify's race; re-proving on the next lap"
			continue
		fi
		if [[ "$verify_rc" = 2 ]]; then
			echo "land: lap $lap — verify refused only because main moved past $(git rev-parse --short origin/main) while it ran; that is a rebase, not a defect. Lapping."
			continue
		fi
		# CLOUD-407: the stop carries the gate's own last words. `verify` now exits
		# 2 for exactly one reason — main moved — so every other non-zero arriving
		# here is a refusal OF THIS TREE, and the thing the operator needs is the
		# `path:line` the refusing step already printed. Pointer-only by
		# inheritance: every gate's output is held to non-negotiable rule 4, and
		# these bytes were on the terminal a moment ago regardless.
		# CLOUD-861, and it precedes the arm below because that arm's advice —
		# "reproduce and fix locally" — is actively wrong here: there is nothing
		# in the diff to fix and nothing to reproduce. `target-prune` runs at lap
		# start and answers "is there room to BEGIN"; the build then consumed
		# 6242MB of certified headroom, so the floor cannot see this class at all.
		# Same misattribution shape CLOUD-811 records in `linear-check`: a task
		# reading every non-zero exit as a verdict about the thing it is about.
		#
		# Pointer-only per non-negotiable rule 4: MB free and the reclaim to run,
		# never a listing of the build tree.
		if [[ "$verify_rc" != 0 ]] && [[ -n "$verify_enospc" ]]; then
			free_mb="$(df -Pm . 2>/dev/null | awk 'NR == 2 { print $4 }')"
			die "verify could not run on $(git rev-parse --short HEAD): the disk filled during it (${free_mb:-unknown}MB free now). This is the environment, NOT this branch — there is nothing here to reproduce. Reclaim and run \`mise run land\` again: \`mise run target-prune\` takes the superseded artifacts, and \`target/debug/incremental\` is the one it cannot (it is never superseded, only unbounded)."
		fi
		[[ "$verify_rc" = 0 ]] ||
			die "verify failed on $(git rev-parse --short HEAD) (exit $verify_rc). Reproduce and fix locally; CI is not where you discover this. Its last words:
$verify_tail"
		mise run verified || die "no verify receipt for HEAD — something swallowed verify's verdict."
	fi

	sha="$(git rev-parse HEAD)"
	remote_before="$(git rev-parse "origin/$branch" 2>/dev/null || echo none)"

	# Readying is the single event that starts CI, and it happens BEFORE the
	# push. This task is the ONLY readier; the workflow contract's step 3 used to
	# ready as well, which is CLOUD-247.
	#
	# The order is the load-bearing part (CLOUD-254). Pushing first and readying
	# after puts two webhooks in the same instant and the same
	# `concurrency: ci-<ref>` group: the `synchronize` event carries
	# `draft: true`, so its run evaluates `if: !draft` and every job is
	# `skipped`, and the `ready_for_review` run does not survive beside it under
	# `cancel-in-progress`. The head ends up carrying a complete set of skipped
	# runs and no graded one, and `ci-wait` polls forever — correctly, since a
	# graded conclusion is what stops draft-era skips reading as green. On #182
	# both events are stamped 22:14:20Z and exactly one run exists, skipped.
	# Readying first makes the push's own `synchronize` the confirming run: one
	# event, carrying `draft: false`, with nothing to contend with.
	#
	# The condition is "this SHA has no graded check-run", not "the PR is a
	# draft" — a head that already carries a graded set must not buy a second run
	# for a SHA that has one, which is step 5 of the contract. Before the push
	# the SHA is usually absent from the remote and the query 404s, which reads
	# as zero: exactly right, since a SHA with no runs is the one that needs the
	# event. `graded` is `ci-wait`'s own list, and deliberately so: "is this set
	# an answer" has one definition, and a second copy here that drifted would
	# put this task back to waiting on runs that will never be graded.
	# --- a deferred decision must have a ticket before review is asked for ---
	#
	# CLOUD-323, and the FOURTH stop this task has. Readying is the commitment to
	# review, which is exactly when "we will decide this later" has to name where
	# later lives. Checked per lap and before the ready block rather than inside
	# it, because that block is conditional and a deferral must not slip through
	# on a lap that happened not to re-ready.
	#
	# `gh pr view` is a read `gh-guard` allows. A body that cannot be fetched
	# fails OPEN — this gate is about what a body says, and a body it never saw
	# is not evidence of anything.
	note_phase "deferral-check(lap $lap)"
	body=$(gh pr view "$pr" --json body --jq .body 2>/dev/null || true)
	if [[ -n "$body" ]] && ! printf '%s' "$body" | mise run deferral-check; then
		die "#$pr defers a decision with no ticket. File it and name the issue in that paragraph, then run land again."
	fi

	# --- and a row this branch FILED must have been groomed before it landed ---
	#
	# CLOUD-514, and the sibling of the stop above: `deferral-check` prices a
	# decision left with no home, this prices a home opened instead of a fix.
	# Filing satisfies every other gate here in seconds while finishing costs a
	# diff, a suite and a landing, so a defect in this branch's own diff is
	# arithmetically cheaper to spin off than to close — unless the new row costs
	# a complete Ready block.
	#
	# No stdin: the record is `board-write-record`'s file under `$GIT_DIR`, keyed
	# to this branch. Reads no tracker, judges no content, and fails open on an
	# absent record — a branch that filed nothing, or predates the recorder, is
	# untouched. Checked per lap and before the ready block for the reason the
	# deferral stop is: that block is conditional, and a lap that happened not to
	# re-ready must not be a way through.
	# THE BODY IS PIPED IN (CLOUD-774), which is what lets the gate exempt a row
	# this PR CLOSES. Without it the gate fires on every row the branch filed and
	# then fixed — their paths are in the diff by construction — so the honest
	# file-then-fix path would need an override every time, and a routinely
	# overridden gate is bypassed rather than satisfied.
	#
	# `$body` is already in hand from the deferral stop above; an empty one (the
	# fetch failed) simply yields no exemption, which is the pre-CLOUD-774
	# behaviour and refuses rather than waves through.
	note_phase "filed-here-check(lap $lap)"
	if ! printf '%s' "$body" | mise run filed-here-check; then
		die "#$pr filed a row that was never groomed to Ready, or names code this branch has open without closing it. Fix it here and close the row, comment on the issue that already owns it, or groom the row and run land again."
	fi

	# --- and the merge must actually move the board -------------------------
	#
	# CLOUD-192, the FIFTH stop. The tracker's merged-event automation fires only
	# for a CLOSING pull request; one that merely mentions its issue links,
	# attaches, and moves nothing. Measured as a pair on one issue with one
	# variable: #398 (`Refs:`) never moved, #400 (`Closes`) moved in two seconds.
	#
	# Same body, fetched once above, and the same fail-open reasoning: a body this
	# never saw is not evidence that the PR closes nothing.
	note_phase "closing-key-check(lap $lap)"
	if [[ -n "$body" ]] && ! printf '%s' "$body" | mise run closing-key-check; then
		die "#$pr names its issue but never closes it, so merging it would leave the board a column behind. Write \"Closes <key>\" in the body (or DO-NOT-CLOSE if this PR is not meant to complete it), then run land again."
	fi

	# --- take the lease before anything can start a run -----------------------
	#
	# Here, and not later: the push below is what starts CI, so acquiring first
	# is what makes "only the holder's matrix runs" true. Not earlier either —
	# `verify` above is purely local work, and holding across it would lengthen
	# every hold for no exclusivity. Its VALIDITY does depend on main, which is
	# CLOUD-392's correction to this comment's older claim: that dependence is
	# answered by racing verify against main-watch (CLOUD-423) and by the
	# per-step receipts that make a re-proof cost seconds (CLOUD-424) — never
	# by holding a fleet-wide lease across a local gate.
	#
	# Before the ready/push pair rather than between them, because that pair is
	# load-bearing and adjacent (CLOUD-254): readying first makes the push's own
	# `synchronize` the confirming run, and anything inserted between them risks
	# the two events landing in one `concurrency: ci-<ref>` group.
	#
	# A lease we cannot win is an ordinary lap, not a failure: `acquire` already
	# waited, so someone else is mid-landing and `main` is about to move. Lapping
	# re-fetches and rebases, and the receipt short-circuit skips `verify` when
	# `main` did not move — so the wait costs a poll, never a CI run.
	note_phase "lease(lap $lap)"
	# The wait count is this branch's AGE, and passing it is what makes the
	# admission fair rather than merely dispersed (CLOUD-369): a branch that has
	# lost repeatedly probes a freed lease sooner than one that just arrived, so
	# no branch spends its whole lap budget while siblings land repeatedly.
	if ! LAND_LOCK_AGE="$lease_waits" mise run land-lock acquire; then
		echo "land: lap $lap — another branch holds the landing lease; lapping rather than spending a run behind it"
		# This lap spent no CI, so it does not count against a backstop that
		# exists to catch "main is moving faster than a lap takes". Counting it
		# would make a busy fleet exhaust LAND_MAX_LAPS on waiting alone and give
		# up without ever having attempted — the opposite of what the lease is
		# for.
		charge_wait

		# --- lost the lease, so do the work that losing makes possible --------
		#
		# Linearize onto the head that is about to become `main`, so this branch's
		# turn — whenever it comes — costs a ready and a push rather than a
		# rebase, a verify and a matrix. `peek` is the machine-readable read;
		# parsing `status`'s prose would make a sentence into an interface.
		speculate "$(mise run land-lock peek branch 2>/dev/null || true)"

		# Then reserve the successor slot. If it is empty this branch becomes the
		# one that may spend the SECOND matrix — the one that overlaps the
		# holder's merge instead of starting cold behind it. One CAS-guarded
		# slot, so exactly one waiter wins it and every other stays in draft: the
		# bound is two whatever N is. A refusal is the ordinary case (somebody
		# reserved first, or we already hold the slot) and costs nothing.
		#
		# AFTER the speculation, deliberately. Being admitted means pushing, and
		# pushing before the linearization would spend the matrix on a head that
		# is already stale — buying exactly the run this design exists to stop
		# buying.
		#
		# TWO CONDITIONS, AND BOTH ARE ABOUT WHETHER THE RUN CAN EVER PAY.
		#
		# GREEN. The second matrix is a favourable bet *because* it is
		# conditioned: a holder that is green AND holds the lease will almost
		# certainly fast-forward, so the successor's run overlaps a merge that is
		# about to happen. Reserving the instant the lease is lost buys it behind
		# a holder whose CI has not answered and may yet come back red — and then
		# the merge never happens, the successor's run is voided, and the
		# mechanism has spent an extra matrix to save nothing. That is the waste
		# this whole issue exists to remove, reappearing inside its own fix.
		#
		# `checks-green` is the one definition of "is this SHA green"
		# (CLOUD-346), asked once rather than polled: 0 green, 1 red, 2 could not
		# look, 3 no answer yet. Only 0 admits. The three non-green answers are
		# all "not yet", and not yet is the safe direction — a lap that declines
		# stays linearized and verified locally and reserves on a later lap for
		# the price of one poll.
		#
		# The read lives HERE and not in `land-lock`, whose suite asserts it
		# never calls `gh`: a lease that reached for the API would become a
		# second authority for CI state as well as for the lock.
		#
		# NO CONFLICT. A base known to conflict cannot pay either, for a
		# different reason: the run is not merely likely to be voided, it is
		# certain to be — `speculate` already declined to linearize onto it, so
		# this branch is not on the base its run would need.
		if [[ "$admitted" = 0 ]] && [[ "$spec_conflicts" = 1 ]]; then
			echo "land: lap $lap — the holder's base conflicts with this branch, so a run behind it could never pay; not reserving"
		elif [[ "$admitted" = 0 ]]; then
			holder_head="$(mise run land-lock peek head 2>/dev/null || true)"
			if [[ -z "$holder_head" ]]; then
				echo "land: lap $lap — the lease names no head, so the holder's CI cannot be read; not reserving"
			elif ! mise run checks-green "$holder_head" >/dev/null 2>&1; then
				echo "land: lap $lap — the holder's run has not gone green, so a second matrix behind it is not yet a bet worth making"
			elif mise run land-lock reserve "$branch" >/dev/null 2>&1; then
				admitted=1
				echo "land: lap $lap — admitted as the successor behind a green holder; this branch may spend the run that overlaps the merge"
			fi
		fi
		# ONCE PER HEAD, not once per lap. A successor that keeps waiting laps
		# repeatedly, and re-entering the ready/push pair each time would push an
		# unchanged head — which emits no `synchronize`, buys nothing, and drops
		# into the `--undo` re-fire path that exists for a different case
		# entirely. The run it wants is already in flight; what it owes now is
		# patience.
		if [[ "$admitted" = 1 ]] && [[ "$admitted_sha" = "$(git rev-parse HEAD)" ]]; then
			echo "land: lap $lap — still the admitted successor, and its run is already in flight"
			continue
		fi
		if [[ "$admitted" = 1 ]]; then
			admitted_sha="$(git rev-parse HEAD)"
			# Fall through WITHOUT the lease: ready and push so the confirming
			# run starts now, then lap. Everything past the push needs the lease
			# — the fast-forward comment above all — so `have_lease` stops this
			# pass there rather than duplicating the ready/push pair, which is
			# the one place CLOUD-254's ordering is written down.
			have_lease=0
		else
			continue
		fi
	else
		have_lease=1
	fi
	# The heartbeat belongs to the HOLDER only. An admitted successor holds
	# nothing to renew, and starting one here would have it renewing somebody
	# else's lease — which `land-lock hold` refuses anyway, but the refusal would
	# be a background process failing silently rather than a thing never started.
	if [[ "$have_lease" = 1 ]]; then
		# LAND_LOCK_HOLDER_PID is CLOUD-432's tether: the heartbeat releases and
		# exits the moment this land stops existing, so a SIGKILL here can no
		# longer leave a lease renewing for nobody.
		LAND_LOCK_HOLDER_PID=$$ mise run land-lock hold >/dev/null 2>&1 &
		heartbeat_pid=$!

		# RE-CONFIRM THE BASE INSIDE THE HOLD (CLOUD-369). `acquire` waits up to a
		# full TTL, and the winner is at its most stale in the instant it wins:
		# `main` may have moved since the rebase at the top of this lap, and the
		# next two statements are a ready and a push that buy a matrix. Confirming
		# here is what makes a speculation safe to act on — and what stops the
		# oldest failure in this loop, a green matrix bought for a head the
		# fast-forward will refuse.
		#
		# Release and lap rather than rebase under the hold: rebasing here would
		# hold a fleet-wide lease across local work, which is the thing the
		# comment above refuses on principle. The lap top rebases and re-verifies,
		# and the receipts make that cheap.
		#
		# It costs no LAP — nothing was spent — but it does count as a WAIT, so
		# the backstop that catches a branch which never gets a turn still fires.
		# Asked as "did `main` MOVE since this lap rebased", not as an ancestry
		# query. They differ where it matters: a lap that speculated is a
		# descendant of a commit that is itself a descendant of main, so
		# `--is-ancestor` passes for exactly the case that must be caught. The
		# sha comparison is also the same question `main-watch` answers, and it
		# costs one rev-parse rather than a graph walk.
		fetch_main
		if [[ "$(git rev-parse origin/main)" != "$lap_main" ]]; then
			echo "land: lap $lap — main moved to $(git rev-parse --short origin/main) while this lap waited for the lease; lapping rather than confirming a head it will refuse"
			drop_lease
			charge_wait
			continue
		fi

		# AND RE-SETTLE THE BET, for the reading `main` cannot answer (CLOUD-495).
		# The top-of-lap settle can be a full TTL old by the time `acquire`
		# returns, and this is the last computable moment before the ready, the
		# push and the fast-forward comment. Winning the lease is itself the
		# strongest evidence a bet is dead: the branch we bet on is not the one
		# holding the lease any more.
		#
		# An unwind here moved HEAD, so `$sha` and this lap's receipts describe a
		# commit this branch no longer has. Lap rather than push from it — the lap
		# top rebases onto `origin/main` and re-verifies, and it costs no lap for
		# the same reason the arm above does not.
		spec_head_before="$(git rev-parse HEAD)"
		settle_speculation
		if [[ "$spec_head_before" != "$(git rev-parse HEAD)" ]]; then
			drop_lease
			charge_wait
			continue
		fi
	fi

	readied=0
	if [[ "$(graded_runs "$sha")" = "0" ]] &&
		[[ "$(gh pr view "$pr" --json isDraft --jq .isDraft 2>/dev/null)" = "true" ]]; then
		gh pr ready "$pr" >/dev/null 2>&1 ||
			die "could not mark #$pr ready for review, so CI would never start."
		readied=1
		echo "land: lap $lap — readied #$pr before pushing, so the push's own event is the one confirming run"
	fi

	# TWO CAUSES, TWO REMEDIES (CLOUD-345). One undifferentiated line named the
	# only cause that was usually NOT true, and it named it toward the dangerous
	# action: "someone else moved the branch" describes a concurrent writer, whose
	# correct response is caution — while the common case is our own merge having
	# deleted the branch, where every check an operator would run (`git log
	# HEAD..origin/<branch>` is empty) says forcing looks safe, for the wrong
	# reason. A message that misnames the cause pushes toward a bare `--force`,
	# which is the one thing the lease exists to prevent.
	#
	# The split is mechanical, not a judgement: absent from the remote is a
	# different state from present at an unexpected SHA. `--force-with-lease` is
	# still what pushes in both — the lease is never weakened to a bare force,
	# which would trade this bug for a worse one.
	if ! git push --force-with-lease -u origin "$branch"; then
		if [[ -z "$(git ls-remote --heads origin "$branch" 2>/dev/null)" ]]; then
			die "push rejected, and \`$branch\` is ABSENT from the remote — this is a stale tracking ref, not a concurrent writer. Our own merge deleted the branch and the local ref outlived it. Do: git fetch --prune origin && mise run land. Do NOT force."
		fi
		die "push rejected, and \`$branch\` IS on the remote at a SHA this clone did not expect. Someone else moved it; look before forcing."
	fi

	# The bet is now PUBLISHED (CLOUD-495). Speculation was justified as free
	# because local execution costs nothing; this is the statement that it stopped
	# being local, and it is what an unwind reads to know the remote is owed a
	# correction too.
	[[ -z "$spec_base" ]] || spec_pushed=1

	base_main="$(git rev-parse origin/main)"

	# A push that moved nothing emitted no `synchronize`, so nothing started a
	# run — and if the head carries only draft-era skips there is no answer to
	# wait for either. This is the #177 shape, and it is the one case that still
	# needs the `--undo` re-fire: converting back to draft and readying again is
	# what actually emits a fresh `ready_for_review` on an unchanged head
	# (`ready-guard` permits the undo since CLOUD-237). Guarded on the ref not
	# moving, so a lap that did push never pays for a second event.
	#
	# And guarded on `readied`, because the two conditions otherwise overlap: a
	# DRAFT on an unchanged head satisfies both, and the lap readied and then
	# immediately re-drafted and readied again — the second `ready_for_review`
	# cancelling the run the first started, through the same
	# `cancel-in-progress` this task relies on elsewhere (CLOUD-255). `--undo`
	# is for a PR that is ALREADY ready; a draft has a cheaper way to emit the
	# event and has just used it.
	if [[ "$readied" = 0 ]] &&
		[[ "$(git rev-parse "origin/$branch")" = "$remote_before" ]] &&
		[[ "$(graded_runs "$sha")" = "0" ]]; then
		gh pr ready "$pr" --undo >/dev/null 2>&1 ||
			die "could not re-draft #$pr to re-fire the ready that starts CI."
		gh pr ready "$pr" >/dev/null 2>&1 ||
			die "could not mark #$pr ready for review, so CI would never start."
		echo "land: lap $lap — the push moved nothing and $(git rev-parse --short "$sha") carries no graded run; re-fired the ready"
	fi

	# THE SUCCESSOR'S PASS ENDS HERE (CLOUD-369). Its matrix is now running
	# alongside the holder's merge, which is the entire point — but everything
	# below needs the lease. Waiting on CI would be the harmless half; commenting
	# `/fast-forward` without holding the lease is the collision the lease exists
	# to prevent, and `held` would refuse it anyway.
	#
	# So: lap. The next pass re-acquires, and by then this branch is linearized,
	# verified AND green — so its turn costs the fast-forward comment and nothing
	# else. That is the cold window closed.
	#
	# `admitted` is deliberately NOT cleared: the reservation stays ours until the
	# lease turns over, and re-reserving every lap would churn the ref to say what
	# it already says.
	if [[ "$have_lease" = 0 ]]; then
		echo "land: lap $lap — pushed as the admitted successor; its run overlaps the merge in flight"
		lap=$((lap - 1))
		continue
	fi

	# --- race the two answers: green, or no longer landable ---
	# LAND_RACE labels which of the two waits this watcher serves. `main-watch`
	# ignores it; it exists so an observer never has to INFER the role from
	# racing state. tests/land.bats used to deduce it from whether a comment had
	# been posted yet — a file this same lap mutates — so a watcher that forked
	# slowly classified itself as the other race and won one it was never
	# scripted to win. That reordering is rare on an idle box and ordinary under
	# a loaded one, which made a real assertion fail only inside a full gate run
	# and pass six times out of six alone (CLOUD-426).
	note_phase "ci-wait(lap $lap)"
	rc_ci="$(mktemp)"
	rc_main="$(mktemp)"
	: >"$rc_ci"
	: >"$rc_main"
	fifo_ci="$(new_rendezvous)" ||
		die "could not create the race rendezvous for the CI wait — the lap cannot wait on two answers without it, and guessing which one won is the false green this race exists to avoid."
	(
		mise run ci-wait
		echo $? >"$rc_ci"
		echo c >"$fifo_ci"
	) &
	ci_pid=$!
	(
		LAND_RACE=ci mise run main-watch "$base_main" >/dev/null 2>&1
		echo $? >"$rc_main"
		echo m >"$fifo_ci"
	) &
	main_pid=$!
	race_pid_a=$ci_pid
	race_pid_b=$main_pid
	# THIS RACE'S OWN RENDEZVOUS, and only these two racers write to it. The
	# property the old `wait -n "$ci_pid" "$main_pid"` bought by naming pids is
	# kept for free here, and it is load-bearing: a bare `wait -n` returns on the
	# FIRST job of any kind to exit, and the lease heartbeat is also a job of this
	# shell — so a heartbeat that ended would read as this race concluding,
	# leaving both result files empty and the lap reporting "no verdict".
	# Measured: it turned every lap of tests/land.bats into a no-verdict lap. A
	# FIFO nobody else writes to cannot be woken by a third job at all.
	await_first "$fifo_ci"
	ciwinner="$AWAIT_WINNER"
	kill -- -"$ci_pid" -"$main_pid" 2>/dev/null
	# NAMED, never bare. A bare `wait` waits for EVERY background job of this
	# shell, and since CLOUD-393 one of them is the lease heartbeat — which by
	# design never exits. So a bare wait here blocks forever, every time, the
	# moment CI answers. Measured: `land` sat at this line for five minutes with
	# every check green and the SHA landable, logging nothing. CLOUD-383 names
	# the shape; the heartbeat turned an intermittent hang into a certain one.
	wait "$ci_pid" "$main_pid" 2>/dev/null
	reap_residue "$ci_pid"
	reap_residue "$main_pid"
	race_pid_a=
	race_pid_b=
	ci_rc="$(cat "$rc_ci" 2>/dev/null)"
	main_rc="$(cat "$rc_main" 2>/dev/null)"
	# CLOUD-510: void the loser, before any arm reads a code. `m` means main-watch
	# won, and a CI verdict on a SHA that is no longer landable is not a verdict
	# about this branch — it is about a run the next lap's push supersedes through
	# `concurrency: cancel-in-progress`. Stopping the landing on it reports a red
	# that nobody needs to fix.
	case "$ciwinner" in
	m) ci_rc="" ;;
	c) main_rc="" ;;
	esac
	rm -f "$rc_ci" "$rc_main"

	if [[ -z "$ci_rc" ]] && [[ "$main_rc" = "0" ]]; then
		echo "land: lap $lap — main moved under ${sha:0:8} before CI finished; that run's verdict is void. Lapping early rather than paying it out."
		cancel_own_run "$sha"
		continue
	fi
	if [[ -n "$ci_rc" ]] && [[ "$ci_rc" != "0" ]]; then
		# `redraft` first on every arm (CLOUD-458): the tap closes on any
		# non-merged exit, whatever the reason turns out to be.
		redraft
		# Three different things arrive here, and only the last one is a red run.
		if declined_by_lease "$branch"; then
			die "the run on ${sha:0:8} was CANCELLED, not red — CI declined it because another branch holds the landing lease (CLOUD-420). Nothing here is broken. Do: git fetch origin main && git rebase origin/main && mise run land"
		fi
		[[ "$ci_rc" = 1 ]] ||
			die "could not read CI's verdict on ${sha:0:8} (ci-wait exit $ci_rc) — that is not a red run, and nothing about this branch has been judged. Do: mise run land"
		# A red that never reached a verdict is not a verdict (CLOUD-483). Tested
		# after the lease arm and before the red message, because both of those
		# are answers about the branch and this one is an answer about the runner.
		if absorbed_transient "$sha"; then
			charge_transient
			continue
		fi
		# THE MATRIX IS ABANDONED HERE, and the position in this arm is the
		# whole of the safety argument (CLOUD-900). Everything above it is a
		# reason the red is NOT a verdict about the tree — a lease decline
		# (CLOUD-420), a run that died before reaching a gate (CLOUD-483) — and
		# both of those are recovered by re-running jobs that a cancellation
		# would put out of reach. Past them the failure is an answer, the rest
		# of the matrix is spending to re-learn it, and `checks-green` now says
		# so the moment the first non-fan-in check goes red rather than waiting
		# for its siblings to finish.
		#
		# Before the `die` rather than after, because `die` does not return; and
		# never guarded into a stop, because a cancellation that fails changes
		# no verdict and must not replace the message below with its own.
		mise run abandon-matrix "$sha" "a required check is red on this head" || true
		die "CI is red on $sha. A red run on a verified branch means verify and CI disagree — fix the mismatch locally, then run land again."
	fi
	if [[ -z "$ci_rc" ]]; then
		# Neither answered (a killed ci-wait with no main movement). Lap rather
		# than guess: the next lap re-reads the checks, and an already-green SHA
		# is answered from the existing check-runs without spending a new run.
		echo "land: lap $lap — no verdict from the wait; re-reading on the next lap"
		continue
	fi

	# --- ask for the merge, then read the answer ---
	#
	# Stamped BEFORE commenting, so a run that predates this lap — an earlier
	# lap of this same PR, refused and since rebased — can never be mistaken
	# for a verdict on this one. Exported for the `--jq` filter below, rather
	# than interpolated into it, so a value can never be read as jq syntax.
	# Now that the task laps by itself the window is load-bearing twice over:
	# without it, lap 2 would read lap 1's refusal and abandon its own attempt
	# instantly, turning the old hang into a livelock.
	note_phase "fast-forward(lap $lap)"
	SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	export SINCE

	# THE FENCE. Ask for the merge only while the lease is still ours. A session
	# paused past its TTL — a throttled VM, a long stall — has been stolen from,
	# and commenting anyway would put two branches in the fast-forward queue at
	# once, which is the collision the lease exists to remove. Cheap stand-in for
	# a fencing token: the lock cannot stop a comment, so the holder checks
	# immediately before making one.
	if ! mise run land-lock held; then
		echo "land: lap $lap — the landing lease was lost before the comment; lapping rather than racing its new holder"
		continue
	fi

	# THE SUCCESS LINE IS A CONSEQUENCE OF THE COMMENT EXISTING, not of control
	# reaching the next line (CLOUD-408). Measured on PR #330: GitHub answered
	# the secondary rate limit on comment creation, `gh` exited non-zero, nothing
	# read it, and `land` printed "commented /fast-forward … waiting for the
	# merge" over a comment that was never created — then blocked waiting for a
	# merge nothing had been asked to perform. Task bodies here do not run under
	# `set -e`, so an unread status is a silent false green; this is the fourth
	# instance of that shape and it is in the one task whose whole job is to
	# drive the lifecycle.
	#
	# `gh api` rather than `gh pr comment`, and not for style: it returns the
	# created comment object, so `.id` — the key the verdict filter below needs
	# (CLOUD-409) — comes back on stdout, and a non-2xx gives both a real
	# non-zero exit and a body worth printing. `gh-guard` allows `gh api`; its
	# `pr comment` rule is about a human hand-typing the directive.
	#
	# `-i` so the RESPONSE HEADERS come back with the body (CLOUD-413): when this
	# is refused, the reason and the delay are stated there, and asking a second
	# endpoint for them would be one more request against the limit that just
	# refused this one. The body split is `main-watch`'s idiom — headers to the
	# first blank line, body after it — so `--jq` is applied here rather than by
	# `gh`, which cannot filter a response it is also printing headers for.
	ff_err="$(mktemp)"
	ff_head="$(mktemp)"
	ff_resp="$(gh api -i "repos/{owner}/{repo}/issues/$pr/comments" \
		-f body="/fast-forward" 2>"$ff_err")"
	printf '%s\n' "$ff_resp" | awk '/^\r?$/ { exit } { print }' >"$ff_head"
	comment_id="$(printf '%s\n' "$ff_resp" |
		awk 'body { print } /^\r?$/ { body = 1 }' |
		jq -r '.id // empty' 2>/dev/null)"
	if [[ -z "$comment_id" ]]; then
		echo "land: lap $lap — could not ask #$pr to fast-forward: $(tr '\n' ' ' <"$ff_err")" >&2
		rm -f "$ff_err"
		# Never enter the answer poll: polling for the answer to a question
		# nobody received is the CLOUD-235 hang with a different cause. The lap
		# ends and the loop laps — but only AFTER the delay the response states,
		# because lapping with no delay is not backoff, it is the same request
		# again, which is what CLOUD-413 measured 24 times.
		rate_limit_pause "$ff_head"
		rm -f "$ff_head"
		unknown="the comment was refused"
		charge_unknown
		continue
	fi
	rm -f "$ff_err" "$ff_head"
	# The join key the workflow mints as its `run-name`, and the filter below
	# matches on it exactly.
	FF_KEY="fast-forward #$pr @$comment_id"
	export FF_KEY
	echo "land: lap $lap — commented /fast-forward on #$pr as comment $comment_id ($sha); waiting for the merge"

	# This wait is raced too (CLOUD-246). The CI wait above got the race and
	# this one did not, which is backwards: a bot that answers nothing is
	# exactly how landing once blocked for 26,123s (~7h15m) on #159 while
	# `main` advanced 10 commits. The two exits below both depend on something
	# external happening — the PR moving, or a run appearing and completing —
	# and neither is guaranteed. `LAND_MAX_LAPS` cannot cover it either: the lap
	# counter only advances when this poll breaks, so a poll that never breaks
	# never reaches the backstop.
	#
	# `main-watch` is the same authority the CI wait races, not a second
	# derivation of "is this SHA still landable". Once `main` moves past this
	# branch the bot's answer can only be "no", whatever it does or does not
	# say, so a win here is an ordinary lap rather than an error.
	rc_ff="$(mktemp)"
	: >"$rc_ff"
	(
		LAND_RACE=answer mise run main-watch "$base_main" >/dev/null 2>&1
		echo $? >"$rc_ff"
	) &
	ff_watch_pid=$!
	race_pid_a=$ff_watch_pid
	race_pid_b=
	# Reap the watcher on every way out of this poll, the merged path included,
	# so no `gh` poller outlives the task that started it. The pid is killed as
	# well as its group, and the `wait` names that pid rather than waiting on
	# everything: the loser of this race blocks indefinitely by construction, so
	# a bare `wait` after a group-kill that did not land would hang here — which
	# is the failure this whole change exists to remove.
	reap_watch() {
		kill "$ff_watch_pid" 2>/dev/null
		kill -- -"$ff_watch_pid" 2>/dev/null
		wait "$ff_watch_pid" 2>/dev/null
		# The wait proves the leader died; only the group check proves the
		# TREE did (CLOUD-434).
		reap_residue "$ff_watch_pid"
		race_pid_a=
		rm -f "$rc_ff"
	}

	refused=""
	moved=""
	unknown=""
	while :; do
		state=$(gh pr view "$pr" --json state --jq .state 2>/dev/null)
		if [[ -n "$state" ]] && [[ "$state" != "OPEN" ]]; then
			reap_watch
			# PRUNING MATTERS MOST EXACTLY HERE (CLOUD-345). This is the merged
			# path — the instant GitHub deletes the head branch, and therefore the
			# instant the local tracking ref becomes the phantom that deadlocks the
			# next reuse of this branch name. Unguarded on purpose: the PR has
			# already reached a terminal state, so a failed fetch changes no verdict.
			git fetch -q --prune origin main
			echo "land: PR #$pr is $state after $lap lap(s); origin/main is now $(git rev-parse --short origin/main)"
			[[ "$state" = "MERGED" ]] || die "PR #$pr is $state — closed without merging."
			# The one exit that must leave the PR alone (CLOUD-458): it landed,
			# so there is no tap to close and nothing left to re-draft.
			landed=yes
			# The branch has done its whole job and trunk-based development is
			# explicit that it should not outlive it: keep the review's
			# commentary, delete the branch (CLOUD-349). A name left behind is
			# how a short-lived branch becomes a long-lived one, and reusing one
			# after its PR merged is the stale-tracking-ref deadlock CLOUD-345
			# records.
			#
			# ONLY here, never on a `die` path: an abandoned branch is evidence
			# and has to survive. And a failure to delete is a warning, not a
			# `die` — the PR has already landed, so reporting failure over
			# cleanup would make a successful landing look like a broken one.
			if git push -q origin --delete "$branch" 2>/dev/null; then
				echo "land: deleted origin/$branch"
			else
				echo "land: could not delete origin/$branch (already gone, or the remote refused) — the PR has landed either way." >&2
			fi
			# THE BRANCH'S FILING HISTORY IS SPENT (CLOUD-774), so the receipts
			# keyed to its name go with it. Every row it filed is now landed,
			# closed by the body, or recorded in the override log; keeping them
			# would judge the NEXT piece of work on this branch name against rows
			# that belong to this one.
			#
			# This is the event-driven half of scoping, and it exists because the
			# obvious predicate does not work. Measured 2026-08-20: after a merge
			# the old base is still an ancestor of HEAD, so "not an ancestor"
			# cannot see a reset; and "equals the current base" excludes rows filed
			# before any ordinary rebase. Neither separates a reset from a rebase.
			# The merge does, exactly, and it is an event rather than an inference.
			#
			# Same posture as the branch delete above: a failure here is silent and
			# harmless, because the landing already succeeded.
			if git_dir=$(git rev-parse --git-dir 2>/dev/null); then
				rm -f "$git_dir/batten-receipts/board-writes.${branch//\//-}" \
					"$git_dir/batten-receipts/filed-here-nudged.${branch//\//-}" 2>/dev/null || true
			fi
			exit 0
		fi

		# THE VERDICT IS KEYED TO THIS PR AND THIS COMMENT, not merely to a
		# timestamp (CLOUD-409, CLOUD-456). An `issue_comment` run attaches
		# to the default-branch tip, so `head_branch` and `head_sha` name
		# `main` on every one of these and no existing field says which PR
		# asked. The window was therefore the `SINCE` stamp and a 20-run
		# page — about 90 seconds — and at the measured cadence (400 runs in
		# 30 minutes, 243 of them refusals) that window is 243 strangers'
		# refusals. Any lap polling after commenting would, with near
		# certainty, find one and report a refusal nobody gave it. That is
		# how "the bot is silent or slow" was inferred while the bot was in
		# fact answering every attempt within 23 seconds.
		#
		# `run-name` in the workflow mints `display_title`; `$FF_KEY` is the
		# same string, built from the comment id the POST returned.
		#
		# BOTH FENCES, and the client-side one is the correctness half. The
		# `created` query parameter bounds the page server-side so page size
		# stops being a silent second window — but a query parameter is an
		# optimisation: mistype it, or meet an endpoint that ignores it, and
		# the fence vanishes with nothing failing. `select(.created_at >=
		# env.SINCE)` is what actually holds the line, and it is what stops
		# an earlier lap's own run being re-read as this lap's verdict —
		# the livelock the stamp exists to prevent.
		#
		# The exit status is READ (CLOUD-414). On a 403 `gh` writes the
		# error body to stdout, the filter fails on it, and the unfiltered
		# body reached `$refused` — where the test was `[ -z ]`, so any
		# non-empty string was a refusal and a transport error was
		# indistinguishable from a verdict. `2>/dev/null` stays: silencing
		# stderr was never the defect, silently trusting stdout was.
		# AND THE DEPTH IS DERIVED FROM THE WINDOW, NEVER FROM A PAGE SIZE
		# (CLOUD-456's second half). The key says WHICH run is this lap's;
		# the depth says whether this lap's run is in the page at all, and
		# they are independent limits on the same read. A keyed filter over
		# a window that has already rolled past the run returns empty, which
		# this loop reads as "not answered yet" — byte-identical to a silent
		# bot, which is the reading that cost CLOUD-399 its diagnosis. At the
		# measured 13 runs/minute one page of 100 is ~7.7 minutes, and a lap
		# routinely outlives that.
		#
		# So this pages until a page comes back short. That terminates
		# because `created>=SINCE` bounds the SET server-side: the pages are
		# a walk over a finite window, not over all history. The 20-page cap
		# is a runaway backstop and nothing else — 2000 runs is ~2.5 hours
		# at the measured rate, far outside any lap's `SINCE`, so reaching it
		# means the `created` fence stopped being honoured, not that the
		# window is genuinely that deep.
		answer=""
		ff_page=1
		while [[ "$ff_page" -le 20 ]]; do
			ff_body="$(gh api \
				"repos/{owner}/{repo}/actions/workflows/$workflow/runs?event=issue_comment&per_page=100&page=$ff_page&created=%3E%3D$SINCE" \
				2>/dev/null)"
			ff_rc=$?
			if [[ "$ff_rc" -ne 0 ]]; then
				answer=unreadable
				break
			fi
			# A body that is not a runs list can never read as an answer.
			ff_seen="$(printf '%s' "$ff_body" | jq -r '
				if (.workflow_runs | type) != "array" then "-"
				else (.workflow_runs | length) end' 2>/dev/null)" || ff_seen=-
			if [[ "$ff_seen" = "-" ]]; then
				answer=unreadable
				break
			fi
			answer="$(printf '%s' "$ff_body" | jq -r '
				[ .workflow_runs[]
				  | select(.created_at >= env.SINCE)
				  | select(.display_title == env.FF_KEY)
				  | select(.status == "completed")
				  | .conclusion // "-" ] | first // empty' 2>/dev/null)" || {
				answer=unreadable
				break
			}
			[[ -n "$answer" ]] && break
			# A short page is the end of the window, which is the whole
			# termination argument — never a fixed number of pages.
			[[ "$ff_seen" -lt 100 ]] && break
			ff_page=$((ff_page + 1))
		done

		case "$answer" in
		"")
			# No keyed run yet. The bot is quiet and this is the ordinary
			# state — keep polling, and forget any earlier unreadable pass.
			answer_unknowns=0
			;;
		success | skipped)
			# It ran and did not refuse; the merge shows up as the PR's
			# terminal state above rather than here.
			answer_unknowns=0
			;;
		failure)
			# A CLOSED VOCABULARY, and `failure` still needs one more read
			# (CLOUD-414). A refusal fails at the action's own step; a
			# `failure` with no failed step, or one that died in `Set up
			# job`, is the bot hitting its own 403 — which judged nothing.
			refused=failure
			break
			;;
		*)
			# `cancelled`, `timed_out`, `startup_failure`, `stale`,
			# `action_required`, `unreadable`: the bot ran and did not
			# decide, or we could not read whether it did. Never "main
			# moved" (CLOUD-413) — that is a fact about a ref, and only
			# `main-watch` may assert it.
			unknown="$answer"
			break
			;;
		esac

		# The other way this lap can end: the bot has said nothing, but `main`
		# has moved past this branch, so there is no answer left worth waiting
		# for. An unmoved `main` and a quiet bot is NOT this case — nothing has
		# changed and the PR may still merge, so that keeps polling.
		if [[ "$(cat "$rc_ff" 2>/dev/null)" = "0" ]]; then
			moved=1
			break
		fi

		sleep "$interval"
	done
	reap_watch

	# THREE OUTCOMES, and they were two (CLOUD-413). Every non-success
	# conclusion — a rate-limited 403 among them — was narrated as "main moved
	# under the branch" and fell into a full lap. Measured across 24 laps of one
	# landing: that diagnosis was wrong twice over, since 7 of 8 laps in one run
	# reached green CI and several refusals were the limit rather than `main`.
	# The loop's response to being rate-limited was to generate more of exactly
	# the request that was rate-limited.
	if [[ -n "$unknown" ]]; then
		echo "land: lap $lap — no readable answer from the fast-forward bot ($unknown); \`main\` has NOT moved, so this is the bot, not the branch. Re-asking."
		charge_unknown
		continue
	fi

	if [[ -n "$moved" ]]; then
		echo "land: lap $lap — main moved under ${sha:0:8} while the bot was still silent, so the fast-forward can only be refused. Lapping: rebase, re-verify, retry."
		continue
	fi

	answer_unknowns=0
	# The branch stopped being a direct descendant, which is what the bot's own
	# step refuses on. Not "main moved" as an inference — that claim belongs to
	# `main-watch` and is made above.
	echo "land: lap $lap — the fast-forward bot refused ($refused); the branch is no longer a direct descendant. Lapping: rebase, re-verify, retry."
done
