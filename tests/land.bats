#!/usr/bin/env bats
# land's driver loop and its stopping conditions, exercised through stub `gh`,
# `git` and `mise` so every one of them is reachable without a real PR.
#
# The refusal condition had no test and was dead code for months (CLOUD-235):
# it filtered the PR head's check-runs for a run the bot never attaches there,
# so it always came back empty and the task polled forever the first time a
# refusal actually arrived. A claim nothing exercises is a claim nothing holds.
#
# So the stub models the API honestly rather than conveniently: it routes by
# endpoint, and the `commits/<sha>/check-runs` endpoint answers EMPTY, because
# that is what GitHub really answers — an `issue_comment`-triggered run attaches
# its check-run to the default-branch tip, never to the PR head. The old filter
# fails these tests; only reading the workflow run's conclusion passes them. The
# stub also pipes real JSON through the real `jq` using the task's own `--jq`
# expression, so the filter is under test and not paraphrased.
#
# CLOUD-238 added the second half: a refusal is no longer where the task ends,
# it is where the next LAP begins. So the discipline here is coverage of every
# way a lap can end — and of lapping itself, asserted by a second full attempt
# rather than by a message about one.
#
# CLOUD-240 added the economies, and they are asserted as SPEND, not as
# messages: a lap whose HEAD already carries a receipt runs no `verify`; a lap
# whose `main` moved never waits out the doomed run; a red run leaves the PR a
# draft, which is the only thing that stops the next push buying another one.
# So the `mise` stub models the receipt rather than a fixed exit status — the
# skip is only real if `verified` answers from what `verify` actually left.

setup() {
	LAND="$BATS_TEST_DIRNAME/../mise-tasks/land"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	# A short interval keeps the polling cases quick; PR is supplied so the
	# stub never has to answer the "which PR" lookup.
	export PATH PR=150 LAND_INTERVAL=1 LAND_ROOT="$BATS_TEST_TMPDIR"
	: >"$BATS_TEST_TMPDIR/comments"
	: >"$BATS_TEST_TMPDIR/gitlog"
	: >"$BATS_TEST_TMPDIR/misecalls"
	stub_gh
	stub_git
	stub_mise
	pr_state OPEN
	workflow_runs runs.last
}

# A fake `gh` covering the three calls land makes. `--jq` is applied with the
# real jq to a real JSON body, so a filter that stops matching fails here.
#
# `pr view` and the workflow-run list are both SEQUENCED: the Nth call reads
# `state.N`/`runs.N`, falling back to `state.last`/`runs.last`. A case therefore
# scripts how the world changes between polls — and between laps — without a
# background sleep deciding the outcome.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
sub="\$1 \$2"
url="\$2"
all="\$*"
filter=""
while [ \$# -gt 0 ]; do
  case "\$1" in --jq) filter="\$2"; shift 2 ;; *) shift ;; esac
done
emit() {
  if [ -n "\$filter" ]; then printf '%s' "\$1" | jq -r "\$filter"; else printf '%s' "\$1"; fi
}
nth() {
  local n
  n=\$(cat "$BATS_TEST_TMPDIR/\$1.calls" 2>/dev/null || echo 0)
  n=\$((n + 1))
  echo "\$n" >"$BATS_TEST_TMPDIR/\$1.calls"
  cat "$BATS_TEST_TMPDIR/\$1.\$n" 2>/dev/null || cat "$BATS_TEST_TMPDIR/\$1.last"
}
case "\$sub" in
  "pr comment")
    echo "\$all" >>"$BATS_TEST_TMPDIR/comments"; echo commented ;;
  "pr ready")
    echo "\$all" >>"$BATS_TEST_TMPDIR/ready"; echo readied ;;
  "pr view")
    case "\$all" in
      *isDraft*) printf '%s' "\$(cat "$BATS_TEST_TMPDIR/isdraft")" ;;
      *)         emit "\$(nth state)" ;;
    esac ;;
  api*)
    case "\$url" in
      # The truth the old implementation got wrong: the bot's run is not here.
      *commits/*check-runs*) emit '{"check_runs":[]}' ;;
      *actions/workflows/*)  emit "\$(nth runs)" ;;
      *)                     emit '{}' ;;
    esac ;;
esac
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/runs.calls" "$BATS_TEST_TMPDIR/state.calls"
	: >"$BATS_TEST_TMPDIR/ready"
	printf 'false' >"$BATS_TEST_TMPDIR/isdraft"
}

# `git` is stubbed too, and each step of a lap that can fail reads its exit
# status from a file, so a case names the one failure it is about.
stub_git() {
	printf 'feat\n' >"$BATS_TEST_TMPDIR/branch"
	local step
	for step in fetch linear rebase push; do
		echo 0 >"$BATS_TEST_TMPDIR/rc.$step"
	done
	cat >"$STUB/git" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/gitlog"
case "\$*" in
  "rev-parse HEAD")              echo cafe1234cafe1234 ;;
  "rev-parse --abbrev-ref HEAD") cat "$BATS_TEST_TMPDIR/branch" ;;
  "rev-parse --short"*)          echo abc1234 ;;
  "rev-parse --show-toplevel")   echo "$BATS_TEST_TMPDIR" ;;
  "fetch"*)                      exit "\$(cat "$BATS_TEST_TMPDIR/rc.fetch")" ;;
  "merge-base"*)                 exit "\$(cat "$BATS_TEST_TMPDIR/rc.linear")" ;;
  "rebase --abort")              exit 0 ;;
  "rebase"*)                     exit "\$(cat "$BATS_TEST_TMPDIR/rc.rebase")" ;;
  "push"*)                       exit "\$(cat "$BATS_TEST_TMPDIR/rc.push")" ;;
  *)                             exit 0 ;;
esac
EOF
	chmod +x "$STUB/git"
}

# `mise` records the tasks a lap runs. It is not a fixed exit status: `verify`
# WRITES the receipt and `verified` reads it, so "an already-proven HEAD is not
# re-proven" is asserted against the real mechanism rather than against a stub
# that was told the answer. `main-watch` blocks forever by default, because a
# quiet `main` losing the race is the normal case; a case that wants it to win
# says so, and says on which lap.
stub_mise() {
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/misecalls"
rc="$BATS_TEST_TMPDIR/rc.mise.\$2"
[ ! -f "\$rc" ] || exit "\$(cat "\$rc")"
case "\$2" in
  verify)   : >"$BATS_TEST_TMPDIR/receipt"; exit 0 ;;
  verified) [ -f "$BATS_TEST_TMPDIR/receipt" ] || exit 1; exit 0 ;;
  ci-wait)  [ ! -f "$BATS_TEST_TMPDIR/ci-wait.slow" ] || sleep 30; exit 0 ;;
  main-watch)
    n=\$(cat "$BATS_TEST_TMPDIR/mw.calls" 2>/dev/null || echo 0)
    n=\$((n + 1)); echo "\$n" >"$BATS_TEST_TMPDIR/mw.calls"
    wins=\$(cat "$BATS_TEST_TMPDIR/mw.wins" 2>/dev/null || echo 0)
    [ "\$n" -le "\$wins" ] || { while :; do sleep 1; done; }
    exit 0 ;;
esac
exit 0
EOF
	chmod +x "$STUB/mise"
	rm -f "$BATS_TEST_TMPDIR/receipt" "$BATS_TEST_TMPDIR/mw.calls" \
		"$BATS_TEST_TMPDIR/mw.wins" "$BATS_TEST_TMPDIR/ci-wait.slow"
}

fails() { echo 1 >"$BATS_TEST_TMPDIR/rc.$1"; }
already_verified() { : >"$BATS_TEST_TMPDIR/receipt"; }
is_draft() { printf 'true' >"$BATS_TEST_TMPDIR/isdraft"; }
ci_is_slow() { : >"$BATS_TEST_TMPDIR/ci-wait.slow"; }
main_moves_on_lap() { echo "$1" >"$BATS_TEST_TMPDIR/mw.wins"; }
ready_calls() { cat "$BATS_TEST_TMPDIR/ready"; }
task_fails() { echo 1 >"$BATS_TEST_TMPDIR/rc.mise.$1"; }
not_linear() { echo 1 >"$BATS_TEST_TMPDIR/rc.linear"; }
comments() { wc -l <"$BATS_TEST_TMPDIR/comments" | tr -d ' '; }

# The Nth `pr view` answers with the Nth argument; the last one sticks.
pr_state() {
	local n=0 s
	for s in "$@"; do
		n=$((n + 1))
		printf '{"state":"%s"}' "$s" >"$BATS_TEST_TMPDIR/state.$n"
	done
	printf '{"state":"%s"}' "${!#}" >"$BATS_TEST_TMPDIR/state.last"
}

# A workflow-run list. With no conclusion given the list is empty — the bot has
# not concluded yet.
workflow_runs() {
	local file="$1" conclusion="${2:-}" created="${3:-2099-01-01T00:00:00Z}"
	if [ -z "$conclusion" ]; then
		printf '{"workflow_runs":[]}' >"$BATS_TEST_TMPDIR/$file"
	else
		printf '{"workflow_runs":[{"created_at":"%s","status":"completed","conclusion":"%s"}]}' \
			"$created" "$conclusion" >"$BATS_TEST_TMPDIR/$file"
	fi
}

@test "a refusal starts the next lap instead of ending the run" {
	# THE REGRESSION, and then its second half. Note the check-runs endpoint is
	# empty throughout, as it is in reality — so the pre-CLOUD-235 filter cannot
	# pass this test, it can only hang. And a task that merely EXITED here would
	# leave one comment, not two: lapping is asserted by a second full attempt,
	# never by a message promising one.
	pr_state OPEN MERGED
	workflow_runs runs.1 failure
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the fast-forward bot refused (failure)"* ]]
	[[ "$output" == *"Lapping: rebase, re-verify, retry"* ]]
	[ "$(comments)" -eq 2 ]
	# And lap 2 re-proves nothing: the rebase was a no-op, so lap 1's receipt
	# still keys to this exact HEAD. Re-running `verify` there would be work
	# with a known answer (CLOUD-240).
	[ "$(grep -c '^run verify$' "$BATS_TEST_TMPDIR/misecalls")" -eq 1 ]
	[[ "$output" == *"already carries a verify receipt"* ]]
}

@test "a cancelled run is a refusal too, not just a failure" {
	pr_state OPEN MERGED
	workflow_runs runs.1 cancelled
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"refused (cancelled)"* ]]
	[ "$(comments)" -eq 2 ]
}

@test "a lap rebases onto the main that moved, then re-verifies the new SHA" {
	# A rebase mints a new SHA, so the previous lap's green is a receipt for a
	# commit that no longer exists — re-running verify is the loop, not waste.
	not_linear
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"rebasing onto"* ]]
	grep -q '^rebase origin/main$' "$BATS_TEST_TMPDIR/gitlog"
	grep -q '^run verify$' "$BATS_TEST_TMPDIR/misecalls"
}

@test "a conflicting rebase is the one stop, and it aborts what it started" {
	# The single step the loop cannot do unattended (AGENTS.md, "When you SHOULD
	# still stop"). Lapping often is what keeps it to one small increment — and
	# leaving a rebase in progress would break the next command run here.
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"conflicts"* ]]
	grep -q '^rebase --abort$' "$BATS_TEST_TMPDIR/gitlog"
	[ "$(comments)" -eq 0 ]
}

@test "a failing verify stops before CI is ever asked" {
	task_fails verify
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"verify failed"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a missing verify receipt stops the lap" {
	# `verified` reads the receipt keyed to this exact HEAD. Landing had no such
	# precondition before, so a branch readied by any other route could still be
	# landed on a verdict nobody checked.
	task_fails verified
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"receipt"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "red CI stops the lap without asking for the merge" {
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a rejected push stops rather than clobbering someone else's branch" {
	# `--force-with-lease` is what makes this a stop and not data loss: the
	# lease is stale the moment another writer moves the branch.
	fails push
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"push rejected"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "an unfetchable origin stops instead of lapping on a stale main" {
	fails fetch
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cannot fetch"* ]]
	[[ "$output" == *"github-access"* ]]
}

@test "endless refusals hit the lap cap rather than lapping forever" {
	# The backstop is on LAPS, never a wall clock on a wait: hitting it means
	# main is moving faster than a lap takes, which a human should see.
	workflow_runs runs.last failure
	LAND_MAX_LAPS=2 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"after 2 laps"* ]]
	[ "$(comments)" -eq 2 ]
}

@test "land refuses to run from main" {
	printf 'main\n' >"$BATS_TEST_TMPDIR/branch"
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"short-lived branch"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a merged PR exits 0" {
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
}

@test "a PR that closed without merging exits non-zero" {
	pr_state CLOSED
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"is CLOSED"* ]]
}

@test "a run still in progress concludes neither way, and the poll continues" {
	# Queued or running is not an answer. Concluding early in either direction
	# is the failure — a premature success reports a landing that never happened.
	pr_state OPEN OPEN OPEN MERGED
	workflow_runs runs.1
	workflow_runs runs.2
	workflow_runs runs.3 failure
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/runs.calls")" -ge 3 ]
	[ "$(comments)" -eq 2 ]
}

@test "a run that predates this lap is not read as a verdict on it" {
	# An earlier lap of the same PR, refused and since rebased, leaves a failed
	# run behind forever. Reading it would make every later lap report a refusal
	# that already happened — so the window is stamped before commenting. Now
	# that the task laps itself the stamp is load-bearing twice over: without it
	# the old hang becomes a livelock, lap 2 abandoning its own attempt on lap
	# 1's answer.
	pr_state OPEN OPEN MERGED
	workflow_runs runs.1 failure 2000-01-01T00:00:00Z
	workflow_runs runs.last failure 2000-01-01T00:00:00Z
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
	[ "$(comments)" -eq 1 ]
}

@test "the merge is what it waits for, not the comment" {
	# A comment plus a guessed sleep is the shape this task replaces: the
	# comment only *starts* the landing.
	pr_state OPEN OPEN MERGED
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(comments)" -eq 1 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/comments")" == *"/fast-forward"* ]]
}

@test "the poll carries no wall-clock timeout" {
	# A hang is fixed by an exit condition that can fire, never by capping the
	# poll — a cap reintroduces the VM-reap gap and would land as a false
	# "refused" on a slow bot. The lap CAP is a count, not a clock.
	run grep -cE '\btimeout [0-9]' "$LAND"
	[ "$output" -eq 0 ]
}

@test "a branch with no PR has nothing to land" {
	# `gh pr view` on a branch with no PR prints nothing, so the lookup for the
	# number comes back empty — an empty body through the real `--jq` is what
	# the stub reproduces.
	rm -f "$BATS_TEST_TMPDIR"/state.[0-9]*
	: >"$BATS_TEST_TMPDIR/state.last"
	PR= run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing to land"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "an already-proven HEAD is not proven again" {
	# `verified` reads the receipt keyed to this exact commit, so when it still
	# holds nothing has changed. Local time is free, but this is also what keeps
	# a lap from being expensive enough to be worth avoiding.
	already_verified
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"already carries a verify receipt"* ]]
	! grep -q '^run verify$' "$BATS_TEST_TMPDIR/misecalls"
	grep -q '^run verified$' "$BATS_TEST_TMPDIR/misecalls"
}

@test "main moving mid-wait starts the next lap instead of paying out the run" {
	# The moment main advances, this SHA cannot fast-forward: the run in flight
	# is already waste and every remaining second of it is billed. So the wait
	# is a RACE, and main-watch winning is a lap, not a failure. Asserted by the
	# lap happening while ci-wait would still have been running.
	ci_is_slow
	main_moves_on_lap 1
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"main moved under"* ]]
	[[ "$output" == *"Lapping early"* ]]
	# Lap 1 never asked for the merge; lap 2 did, once.
	[ "$(comments)" -eq 1 ]
}

@test "a red CI re-drafts the PR before stopping" {
	# CI does not run on drafts, so this is the only thing that stops the next
	# push — from any source — buying another run over a failure nobody has
	# fixed yet. Stopping without it leaves the tap open.
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
	[[ "$output" == *"re-drafted"* ]]
	[[ "$(ready_calls)" == *"--undo"* ]]
}

@test "a draft PR is readied, which is the event that spends the run" {
	# Readying is what starts CI, so it happens once the tree is proven and
	# pushed and never earlier — and it is how a PR re-drafted by an earlier red
	# run resumes the loop without a human.
	is_draft
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"readied #150"* ]]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "nothing is readied when the PR is already ready" {
	# Re-readying a ready PR is a no-op to GitHub but a lie in the log, and the
	# lie is the one that matters: it reads as a second run being started.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ ! -s "$BATS_TEST_TMPDIR/ready" ]
}

@test "every way a lap can end is exercised above" {
	# The property that would have caught the dead branch: an exit nothing
	# reaches is an exit nothing tests. Each `die` is covered by a case here,
	# so a new stopping condition cannot be added silently.
	stops=$(grep -o 'die "' "$LAND" | wc -l | tr -d ' ')
	[ "$stops" -eq 10 ] || {
		echo "land has $stops stopping conditions; this suite covers 10."
		echo "Add a case for the new one — an unexercised exit is how the refusal path stayed dead."
		return 1
	}
}
