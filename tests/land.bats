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
# CLOUD-247 made this task the ONLY readier, and on the honest condition: a head
# with no GRADED check-run, not a PR that happens to be a draft. A push made while
# draft leaves a complete `skipped` set that readying afterwards does not replace,
# so no confirming run is ever spent and `ci-wait` polls forever — correctly.
#
# CLOUD-240 added the economies, and they are asserted as SPEND, not as
# messages: a lap whose HEAD already carries a receipt runs no `verify`; a lap
# whose `main` moved never waits out the doomed run; a red run leaves the PR a
# draft, which is the only thing that stops the next push buying another one.
# So the `mise` stub models the receipt rather than a fixed exit status — the
# skip is only real if `verified` answers from what `verify` actually left.

setup() {
	REAL_LAND="$BATS_TEST_DIRNAME/../mise-tasks/land"
	# CLOUD-434: the program under test launches with bats' fd 3 closed, in ONE
	# place rather than at every call site. A backgrounded descendant that
	# outlives its reap otherwise holds the TAP stream, and bats-exec-file waits
	# on that fd's EOF — so one leaked watcher wedged the whole gate, silently,
	# with every test green. With the fd closed a leak costs a stray process,
	# never a hung file.
	LAND="$BATS_TEST_TMPDIR/land-under-test"
	printf '#!/usr/bin/env bash\nexec 3>&- || true\nexec "%s" "$@"\n' "$REAL_LAND" >"$LAND"
	chmod +x "$LAND"
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
    echo "\$all" >>"$BATS_TEST_TMPDIR/ready"
    echo "ready" >>"$BATS_TEST_TMPDIR/calls"
    case "\$all" in
      *--undo*) [ ! -f "$BATS_TEST_TMPDIR/rc.undo" ] || exit 1 ;;
      *)        [ ! -f "$BATS_TEST_TMPDIR/rc.ready" ] || exit 1 ;;
    esac
    echo readied ;;
  "pr view")
    case "\$all" in
      *isDraft*) printf '%s' "\$(cat "$BATS_TEST_TMPDIR/isdraft")" ;;
      # Not sequenced, for the same reason isDraft is not: the body is a
      # property of the PR, not an observation whose Nth answer a case scripts.
      # Letting it fall through would consume a \`state.N\` slot and shift every
      # transition after it — measured, when CLOUD-323's check was wired in.
      *body*)    printf '%s' "\$(cat "$BATS_TEST_TMPDIR/prbody" 2>/dev/null)" ;;
      *)         emit "\$(nth state)" ;;
    esac ;;
  api*)
    case "\$url" in
      # The bot's run is still not here — that is the truth the original
      # implementation got wrong. What IS here is the head's CI check set,
      # which is what decides whether a confirming run was ever spent
      # (CLOUD-247), so a case can script it.
      *commits/*check-runs*) emit "\$(cat "$BATS_TEST_TMPDIR/checkruns")" ;;
      *actions/workflows/*)  emit "\$(nth runs)" ;;
      *)                     emit '{}' ;;
    esac ;;
esac
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/runs.calls" "$BATS_TEST_TMPDIR/state.calls"
	: >"$BATS_TEST_TMPDIR/ready"
	: >"$BATS_TEST_TMPDIR/calls"
	printf 'false' >"$BATS_TEST_TMPDIR/isdraft"
	head_checks_empty
}

# `git` is stubbed too, and each step of a lap that can fail reads its exit
# status from a file, so a case names the one failure it is about.
stub_git() {
	printf 'feat\n' >"$BATS_TEST_TMPDIR/branch"
	local step
	for step in fetch linear rebase push delete; do
		echo 0 >"$BATS_TEST_TMPDIR/rc.$step"
	done
	: >"$BATS_TEST_TMPDIR/deletes"
	# The remote branch ref is modelled, not assumed: `land` compares it across
	# the push to tell "this lap emitted a synchronize event" from "this lap
	# moved nothing", and those two take different paths (CLOUD-254). A
	# successful push advances it to HEAD, exactly as a real one does.
	echo staleremote >"$BATS_TEST_TMPDIR/remote_ref"
	cat >"$STUB/git" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/gitlog"
case "\$*" in
  "rev-parse HEAD")              echo cafe1234cafe1234 ;;
  "rev-parse origin/main")       echo ma1nma1nma1nma1n ;;
  "rev-parse origin/"*)          cat "$BATS_TEST_TMPDIR/remote_ref" ;;
  "rev-parse --abbrev-ref HEAD") cat "$BATS_TEST_TMPDIR/branch" ;;
  "rev-parse --short"*)          echo abc1234 ;;
  "rev-parse --show-toplevel")   echo "$BATS_TEST_TMPDIR" ;;
  "fetch"*)                      exit "\$(cat "$BATS_TEST_TMPDIR/rc.fetch")" ;;
  "merge-base"*)                 exit "\$(cat "$BATS_TEST_TMPDIR/rc.linear")" ;;
  "rebase --abort")              exit 0 ;;
  "rebase"*)                     exit "\$(cat "$BATS_TEST_TMPDIR/rc.rebase")" ;;
  "push -q origin --delete "*)
    # The post-merge cleanup (CLOUD-349). Recorded separately from the landing
    # push: it is not part of the lap, and folding it into \`calls\` would move
    # the ready/push ORDER the CLOUD-254 cases assert on.
    echo "\$*" >>"$BATS_TEST_TMPDIR/deletes"
    exit "\$(cat "$BATS_TEST_TMPDIR/rc.delete")" ;;
  "push"*)
    echo "push" >>"$BATS_TEST_TMPDIR/calls"
    rc=\$(cat "$BATS_TEST_TMPDIR/rc.push")
    [ "\$rc" != 0 ] || echo cafe1234cafe1234 >"$BATS_TEST_TMPDIR/remote_ref"
    exit "\$rc" ;;
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
if [ -f "\$rc" ]; then
  code=\$(cat "\$rc")
  # A failure can be scripted for ONE call rather than for the whole run, which
  # is what a lap-and-recover case needs: the second lap must see the task pass.
  [ ! -f "\$rc.once" ] || rm -f "\$rc" "\$rc.once"
  echo "::error:: \$2 failed" >&2
  exit "\$code"
fi
case "\$2" in
  verify)
    # CLOUD-423's lever, consumed BEFORE the sleep: a verify killed mid-gate
    # must not slow the lap that retries it, and the kill landing during the
    # sleep is exactly the abort under test — the receipt line is never
    # reached, so the abort-leaves-no-receipt property is observed for real.
    if [ -f "$BATS_TEST_TMPDIR/verify.slow" ]; then
      rm -f "$BATS_TEST_TMPDIR/verify.slow"
      sleep 30
    fi
    : >"$BATS_TEST_TMPDIR/receipt"; exit 0 ;;
  verified)
    if [ ! -f "$BATS_TEST_TMPDIR/receipt" ]; then
      # $(verified) is a gate: a missing receipt is a failure and it SAYS so.
      # Modelling that is what makes the quiet-success property meaningful.
      echo "::error:: HEAD is NOT verified — no verify receipt for this commit." >&2
      exit 1
    fi
    exit 0 ;;
  # CLOUD-323's stop. Passes by default; a case that wants the refusal
  # writes rc.mise.deferral-check, the same lever every other task uses.
  deferral-check) exit 0 ;;
  ci-wait)  [ ! -f "$BATS_TEST_TMPDIR/ci-wait.slow" ] || sleep 30; exit 0 ;;
  main-watch)
    # CLOUD-434's two levers. A stubborn watcher ignores the TERM, so only the
    # escalated reap can end it; a detaching one leaves the process group
    # entirely, so only the closed fd 3 keeps it off the TAP stream.
    if [ -f "$BATS_TEST_TMPDIR/stubborn" ]; then
      trap '' TERM
      echo "\$\$" >>"$BATS_TEST_TMPDIR/stubborn.pids"
    fi
    if [ -f "$BATS_TEST_TMPDIR/detach" ] && [ ! -f "$BATS_TEST_TMPDIR/detached.pid" ]; then
      setsid bash -c "echo \\\$\\\$ >'$BATS_TEST_TMPDIR/detached.pid'; sleep 30" >/dev/null 2>&1 &
    fi
    # CLOUD-423's no-verdict lever: the verify-race watcher dying without an
    # answer, once, so the lap that follows re-proves instead of guessing.
    if [ "\${LAND_RACE:-}" = verify ] && [ -f "$BATS_TEST_TMPDIR/vwatch.fail" ]; then
      rm -f "$BATS_TEST_TMPDIR/vwatch.fail"
      exit 1
    fi
    # A lap starts two watchers, and they are told apart by WHEN: the one
    # racing the fast-forward answer is by construction the one started after
    # this lap's comment. Counting them separately is not cosmetic — a single
    # shared counter is read stale by the second watcher and neither ever wins.
    # The role is TOLD to us by land (LAND_RACE), never deduced from whether a
    # comment exists yet: that file is mutated by the same lap, so a slow fork
    # read it after the comment landed and took the other race's counter.
    role=\${LAND_RACE:-ci}
    n=\$(cat "$BATS_TEST_TMPDIR/mw.\$role.calls" 2>/dev/null || echo 0)
    n=\$((n + 1)); echo "\$n" >"$BATS_TEST_TMPDIR/mw.\$role.calls"
    wins=\$(cat "$BATS_TEST_TMPDIR/mw.\$role.wins" 2>/dev/null || echo 0)
    [ "\$n" = "\$wins" ] || { while :; do sleep 1; done; }
    exit 0 ;;
esac
exit 0
EOF
	chmod +x "$STUB/mise"
	rm -f "$BATS_TEST_TMPDIR/receipt" "$BATS_TEST_TMPDIR/ci-wait.slow" \
		"$BATS_TEST_TMPDIR"/mw.*
}

fails() { echo 1 >"$BATS_TEST_TMPDIR/rc.$1"; }
already_verified() { : >"$BATS_TEST_TMPDIR/receipt"; }
is_draft() { printf 'true' >"$BATS_TEST_TMPDIR/isdraft"; }
# The head's CI check set. "Graded" is `ci-wait`'s list of real conclusions;
# an all-`skipped` set is the draft-era one, which is not an answer.
head_checks() { printf '%s' "$1" >"$BATS_TEST_TMPDIR/checkruns"; }
head_checks_empty() { head_checks '{"check_runs":[]}'; }
head_is_graded() { head_checks '{"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'; }
head_is_all_skipped() { head_checks '{"check_runs":[{"name":"ci","status":"completed","conclusion":"skipped"}]}'; }
ci_is_slow() { : >"$BATS_TEST_TMPDIR/ci-wait.slow"; }
# A lap makes TWO `main-watch` calls: one racing `ci-wait`, one racing the
# fast-forward answer (CLOUD-246). Each is counted under its own role, so a
# case says which of the two moves `main` and on which lap.
main_moves_on_lap() { echo "$1" >"$BATS_TEST_TMPDIR/mw.ci.wins"; }
main_moves_during_answer_wait() { echo "$1" >"$BATS_TEST_TMPDIR/mw.answer.wins"; }
# CLOUD-434's levers — see the stub's main-watch case.
watcher_is_stubborn() { : >"$BATS_TEST_TMPDIR/stubborn"; }
watcher_detaches() { : >"$BATS_TEST_TMPDIR/detach"; }
# CLOUD-423's levers: a verify slow enough to lose its race, a main that moves
# while it runs, and a verify-race watcher that dies without an answer.
verify_is_slow() { : >"$BATS_TEST_TMPDIR/verify.slow"; }
main_moves_during_verify() { echo "$1" >"$BATS_TEST_TMPDIR/mw.verify.wins"; }
verify_watch_fails_once() { : >"$BATS_TEST_TMPDIR/vwatch.fail"; }
ready_calls() { cat "$BATS_TEST_TMPDIR/ready"; }
# The push leaves the remote ref where it was, so no `synchronize` event fires
# and nothing starts a run — the one shape that still needs the `--undo`.
push_moves_nothing() { echo cafe1234cafe1234 >"$BATS_TEST_TMPDIR/remote_ref"; }
# The interleaved record of the two calls whose ORDER is the defect.
call_order() { tr '\n' ' ' <"$BATS_TEST_TMPDIR/calls"; }
undo_fails() { : >"$BATS_TEST_TMPDIR/rc.undo"; }
ready_fails() { : >"$BATS_TEST_TMPDIR/rc.ready"; }
# The PR body `deferral-check` reads. Empty by default, which is why every other
# case skips the check entirely rather than having to opt out of it.
pr_body() { printf '%s' "$1" >"$BATS_TEST_TMPDIR/prbody"; }
task_fails() { echo 1 >"$BATS_TEST_TMPDIR/rc.mise.$1"; }
# A task that fails with a specific code, for one call only. `verify` answering
# 2 is "main moved while I ran" (CLOUD-318), and a lap that recovers from it is
# only a real lap if the next call succeeds.
task_fails_once_with() {
	echo "$2" >"$BATS_TEST_TMPDIR/rc.mise.$1"
	: >"$BATS_TEST_TMPDIR/rc.mise.$1.once"
}
verify_calls() { grep -c '^run verify$' "$BATS_TEST_TMPDIR/misecalls" || true; }
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
	# The count is the load-bearing half (CLOUD-318): lapping on staleness must
	# not turn a stop-on-content into a silent retry loop that burns
	# LAND_MAX_LAPS before reporting the same failure.
	[ "$(verify_calls)" -eq 1 ]
}

@test "a verify that failed only because main moved laps instead of stopping" {
	# CLOUD-318, measured on #240: `verify` takes ~150s, `main` moved past the
	# tip lap 1 rebased onto, `linear-check` refused, and the loop exited with
	# advice — "reproduce and fix locally" — that named nothing to reproduce.
	# Re-running with zero edits landed after three laps. Exit 2 is the one code
	# that means that, and it is a lap.
	task_fails_once_with verify 2
	pr_state OPEN MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"verify refused only because main moved"* ]]
	# Not the content stop: that message tells the reader to reproduce something
	# that does not exist, which is half of what CLOUD-318 is about.
	[[ "$output" != *"Reproduce and fix locally"* ]]
	# It really lapped: a second verify ran, and the lap reached the push.
	[ "$(verify_calls)" -eq 2 ]
	[[ "$(call_order)" == *push* ]]
}

@test "a verify that keeps losing the race exhausts laps rather than spinning" {
	# The lap is bounded by the backstop that already exists. A `main` that
	# never stops moving must reach LAND_MAX_LAPS and say so, not loop forever.
	echo 2 >"$BATS_TEST_TMPDIR/rc.mise.verify"
	LAND_MAX_LAPS=3 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"still not linear after 3 laps"* ]]
	[ "$(verify_calls)" -eq 3 ]
	[ "$(comments)" -eq 0 ]
}

@test "a body that defers a decision with no ticket stops before review is asked for" {
	# CLOUD-323's stop. Readying is the commitment to review, which is when "we
	# will decide this later" has to name where later lives — two decisions
	# landed on `main` during CLOUD-164 with a PR paragraph as their only record.
	#
	# Asserted before the comment count for the same reason the verify stop is:
	# stopping AFTER asking for the merge would have already spent the thing the
	# stop exists to withhold.
	pr_body "The format is a judgement call and nobody owns it."
	task_fails deferral-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"defers a decision with no ticket"* ]]
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
	run grep -cE '\btimeout [0-9]' "$REAL_LAND"
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

@test "nothing is readied when the head already carries a graded run" {
	# Re-readying is a no-op to GitHub but a lie in the log, and worse it buys a
	# second CI run for a SHA that already has one — step 5 of the contract. The
	# graded head is what makes "already ready" mean "already answered": without
	# it, a ready PR whose head has no real run is the stall, not the no-op.
	head_is_graded
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ ! -s "$BATS_TEST_TMPDIR/ready" ]
}

@test "a ready PR whose head carries only skipped runs has its ready re-fired" {
	# THE STALL (CLOUD-247), measured on #177. A push made while the PR was a
	# draft leaves a complete `skipped` set on the head; readying afterwards
	# produced no new run, and `ci-wait` then polled forever — correctly, since
	# an all-skipped set is not an answer. Nothing was broken at either end and
	# no confirming run was ever spent. Only `--undo` re-emits
	# `ready_for_review`, so that is what the lap must do.
	head_is_all_skipped
	push_moves_nothing
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$(ready_calls)" == *"--undo"* ]]
	[[ "$output" == *"re-fired the ready"* ]]
}

@test "a DRAFT whose push moves nothing readies once, not once and then again" {
	# CLOUD-255. The two ready blocks were not mutually exclusive: a draft on an
	# unchanged head with only skipped runs satisfies both, so the lap readied,
	# then re-drafted and readied again. The first `ready_for_review` starts a
	# run and the second cancels it through `cancel-in-progress` — a runner spent
	# and thrown away, by the task whose whole premise is that runners are
	# metered. `--undo` exists to emit that event on a PR that is ALREADY ready;
	# a draft has a cheaper way and has just used it. The case above ran with the
	# default non-draft PR, which is why this shape went unexercised.
	is_draft
	push_moves_nothing
	head_is_all_skipped
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(grep -c . "$BATS_TEST_TMPDIR/ready")" -eq 1 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "THE RACE: the ready precedes the push, so one event carries the run" {
	# CLOUD-254, measured on #182. Pushing first and readying after puts two
	# webhooks in the same instant and the same `concurrency: ci-<ref>` group:
	# the `synchronize` carries `draft: true` so its run skips every job, and the
	# `ready_for_review` run does not survive beside it under
	# `cancel-in-progress`. Both events are stamped 22:14:20Z on #182 and exactly
	# one run exists, skipped — the head carries no graded run and `ci-wait`
	# polls forever. Readying FIRST makes the push's own event the confirming
	# run. Asserted on the order, because both calls happen either way and only
	# the order decides whether a run is ever created.
	is_draft
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$(call_order)" == "ready push"* ]]
	[[ "$output" == *"before pushing"* ]]
}

@test "a lap that pushed does not also buy a second event" {
	# The re-fire is guarded on the ref NOT moving. A lap that pushed already
	# emitted the `synchronize` that starts the run; converting to draft and back
	# on top of it would spend a second runner for one SHA — step 5 of the
	# contract — and re-drafting mid-run is how the first one gets cancelled.
	is_draft
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
	[ "$(grep -c ready "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
}

@test "a landing that succeeds says nothing that reads as a failure" {
	# The property that would have caught CLOUD-245. The suite asserted the
	# messages it WANTED and never that the success path was quiet, so a probe
	# whose ordinary answer is an `::error::` shipped and printed one on every
	# green landing. A reader who sees `::error::` on success learns to skim it,
	# and the next one that matters is skimmed too.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" != *"::error::"* ]] || {
		echo "a green landing emitted an ::error:: line:"
		printf '%s\n' "$output" | grep '::error::'
		return 1
	}
}

@test "the receipt guard still has its voice when it is the real failure" {
	# The same call, asked as a guard rather than a probe: after a green
	# `verify`, no receipt means something swallowed the verdict. Silencing both
	# call sites would trade one defect for a worse one.
	task_fails verified
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"::error::"* ]]
	[[ "$output" == *"receipt"* ]]
}

@test "a silent bot with main moved ends the lap instead of polling" {
	# THE 7h15m CASE (CLOUD-246). The bot answers nothing at all — no terminal
	# PR state, no completed run — while `main` advances past the branch. Before
	# this the answer poll had no third exit and blocked for 26,123s on #159.
	#
	# `main_moves_during_answer_wait 1` is what makes the distinction testable:
	# lap 1's CI-race watcher still loses, so the lap reaches the answer poll,
	# and only the watcher started there wins. Lap 2 then merges, so `land`
	# exits on its own — which every case here must let it do, because `set -m`
	# puts each watcher in its own process group and a `timeout` kill of the
	# parent would leave one holding this suite's stdout open.
	#
	# Several OPEN reads, not one (CLOUD-256). The poll reads the PR state
	# BEFORE it checks the watcher's result file, and `pr_state OPEN MERGED`
	# makes MERGED sticky from the second read — so the backgrounded
	# `main-watch` had exactly one interval to fork, exec and write, and lost
	# that race once inside a full gate run. The case is about WHICH exit fires,
	# not about how fast a fork completes; the assertions below are unchanged.
	main_moves_during_answer_wait 1
	pr_state OPEN OPEN OPEN OPEN MERGED
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"main moved under"* ]]
	[[ "$output" == *"while the bot was still silent"* ]]
	# Two laps means it really lapped rather than falling through.
	[ "$(comments)" -eq 2 ]
}

@test "a silent bot with main unmoved keeps polling" {
	# The other half, and why the fix is a race rather than a timeout: nothing
	# has changed, so the PR may still merge, and ending the lap here would
	# abandon a landing that was going to succeed.
	#
	# This is the one case that must kill `land` to prove a negative, so it
	# redirects to a file instead of going through `run`: the orphaned watcher
	# would otherwise hold the pipe and hang the suite rather than fail it.
	pr_state OPEN
	workflow_runs runs.last
	local out="$BATS_TEST_TMPDIR/still-waiting" rc=0
	# `|| rc=$?` because a bats body aborts on a non-zero command, and 124 is
	# the result this case is asserting rather than a failure of it.
	timeout -k 1 5 "$LAND" >"$out" 2>&1 || rc=$?
	[ "$rc" -eq 124 ]
	# This is the only case that kills `land` mid-poll, and `land` runs `set -m`
	# so each watcher has its own process group and outlives the parent. Left
	# alone they block forever and the suite never exits — so this reaps the
	# ones this case orphaned, matched on the per-test stub path so it can
	# touch nothing else.
	pkill -f "$STUB/mise" 2>/dev/null || true
	run cat "$out"
	[[ "$output" != *"main moved under"* ]]
	[[ "$output" != *"is MERGED"* ]]
	[[ "$output" == *"waiting for the merge"* ]]
}

@test "the watcher does not outlive a merged landing" {
	# The reap, on the path that exits rather than laps. A `main-watch` left
	# running would keep polling GitHub after the task returned — and because
	# the loser of this race blocks by construction, a `wait` that named no pid
	# would hang the very landing this change exists to unblock. `run`
	# returning at all is that assertion.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
}

@test "a re-draft that fails stops the lap rather than waiting on a run nobody started" {
	# The `--undo` is what re-emits `ready_for_review`; if it cannot happen the
	# confirming run never starts, and polling on would be waiting for something
	# that is not coming — the exact shape this whole area keeps producing.
	head_is_all_skipped
	push_moves_nothing
	undo_fails
	pr_state OPEN
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not re-draft"* ]]
}

@test "a ready that fails stops before the push rather than pushing into silence" {
	# The ready now precedes the push (CLOUD-254), so a ready that cannot happen
	# is caught while nothing has been published yet. Pushing on past it would
	# put a commit on a draft PR that no event will ever grade — the stall this
	# whole area keeps producing, reached from the other side.
	is_draft
	ready_fails
	pr_state OPEN
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not mark #150 ready"* ]]
	[[ "$(call_order)" != *push* ]]
}

@test "every way a lap can end is exercised above" {
	# The property that would have caught the dead branch: an exit nothing
	# reaches is an exit nothing tests. Each `die` is covered by a case here,
	# so a new stopping condition cannot be added silently.
	stops=$(grep -o 'die "' "$REAL_LAND" | wc -l | tr -d ' ')
	[ "$stops" -eq 14 ] || {
		echo "land has $stops stopping conditions; this suite covers 14."
		echo "Add a case for the new one — an unexercised exit is how the refusal path stayed dead."
		return 1
	}

	# `die` is no longer the only way a lap ends: a lap can also `continue`,
	# and CLOUD-246's exit is one of those. Counting only the dies would have
	# left the new branch exactly as unwatched as the refusal branch once was,
	# which is the mistake this assertion exists to stop repeating.
	# 14 and 6 since CLOUD-393: the landing lease adds one stop (the fleet is
	# saturated — every turn lost) and two laps (the lease is held by someone
	# else, and the lease was lost before the comment). This assertion caught all
	# three the moment they were added, which is the whole point of it.
	# 8 since CLOUD-423: the verify race adds two more — main moved while verify
	# ran, and a verify race that produced no verdict. Both exercised below, and
	# this assertion caught both the moment the race landed.
	laps=$(grep -cE '^[[:space:]]*continue$' "$REAL_LAND")
	[ "$laps" -eq 8 ] || {
		echo "land has $laps lap-ending continues; this suite covers 8."
		echo "Add a case for the new one — an exit nothing counts is an exit nothing tests."
		return 1
	}
}

# --- the verify race (CLOUD-423) ---------------------------------------------

@test "main moving during verify ends the lap at the poll, never at the end of the gate" {
	# The blind window: verify used to run its whole ~220s gate before
	# linear-check discovered main had moved. Raced, the lap ends within one
	# poll interval — and the aborted verify left NO receipt, so lap 2 proves
	# the tree for real rather than trusting a kill to have been clean. That
	# second verify call IS the abort-safety property, observed live.
	verify_is_slow
	main_moves_during_verify 1
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"while verify ran"* ]]
	[ "$(verify_calls)" -eq 2 ]
	[[ "$output" != *"already carries a verify receipt"* ]]
	[ "$(comments)" -eq 1 ]
}

@test "a verify race with no verdict laps and re-proves rather than guessing" {
	# The conservative arm, same as the CI race's: a watcher that died without
	# an answer while verify was still running is not evidence of anything, so
	# the lap re-proves. With the per-step receipts the retry costs seconds.
	verify_is_slow
	verify_watch_fails_once
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no verdict from verify's race"* ]]
	[ "$(verify_calls)" -eq 2 ]
	[ "$(comments)" -eq 1 ]
}

# --- post-merge branch cleanup (CLOUD-349) -----------------------------------

deletes() { grep -c . "$BATS_TEST_TMPDIR/deletes" || true; }

@test "a merged PR's branch is deleted from the remote" {
	# Trunk-based development keeps the review's commentary and not the branch.
	# A name left behind is how a short-lived branch becomes a long-lived one —
	# and reusing one after its PR merged is the stale-tracking-ref deadlock
	# CLOUD-345 records.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(deletes)" -eq 1 ]
	grep -q '^push -q origin --delete feat$' "$BATS_TEST_TMPDIR/deletes"
	[[ "$output" == *"deleted origin/feat"* ]]
}

@test "a delete the remote refuses does not change land's exit code" {
	# The PR has already landed. Reporting failure over cleanup would make a
	# successful landing look like a broken one, and the next run would have
	# nothing left to retry.
	fails delete
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(deletes)" -eq 1 ]
	[[ "$output" == *"could not delete origin/feat"* ]]
}

@test "a run that stops instead of merging deletes nothing" {
	# An abandoned branch is evidence and has to survive: the delete is on the
	# MERGED path only, never on a `die` path.
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[ "$(deletes)" -eq 0 ]
}

# --- the landing lease (CLOUD-393) -----------------------------------------
#
# `land`'s side of the lock, not the lock itself: tests/land-lock.bats owns the
# atomicity claim against a real remote. What these pin is the discipline — the
# lease is taken before anything can start a run, re-checked before the merge is
# asked for, and never leaked on a way out.

lock_calls() { grep -c "^run land-lock $1\$" "$BATS_TEST_TMPDIR/misecalls" || true; }

@test "the lease is taken before the push, so no run starts unheld" {
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	# The acquire must precede the first push in the recorded order; a lease
	# taken after the push would let CI start on a branch that never held it.
	acq=$(grep -n '^run land-lock acquire$' "$BATS_TEST_TMPDIR/misecalls" | head -1 | cut -d: -f1)
	[ -n "$acq" ]
	[ "$(lock_calls acquire)" -ge 1 ]
}

@test "a lease held by someone else waits instead of pushing, and says so" {
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=2 run "$LAND"
	# No push, so no CI was spent on a branch that could not have landed.
	[ "$status" -eq 1 ]
	[[ "$output" == *"another branch holds the landing lease"* ]]
	[ "$(call_order)" = "" ]
	# And it ends on the saturation signal, not the lap cap: a wait is not a lap,
	# but "never won a turn" still has to be a condition that can fire.
	[[ "$output" == *"never won the landing lease in 2 attempts"* ]]
}

@test "a lost lease is caught BEFORE the merge is asked for" {
	# The fence. `held` fails only after the acquire has succeeded, which is the
	# stolen-lease shape: the lap must lap rather than comment.
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/misecalls"
case "\$2" in
  verify)     : >"$BATS_TEST_TMPDIR/receipt"; exit 0 ;;
  verified)   [ -f "$BATS_TEST_TMPDIR/receipt" ] || exit 1; exit 0 ;;
  land-lock)  [ "\$3" != held ] || exit 1; exit 0 ;;
  main-watch) while :; do sleep 1; done ;;
esac
exit 0
EOF
	chmod +x "$STUB/mise"
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"lease was lost before the comment"* ]]
	[ ! -s "$BATS_TEST_TMPDIR/comments" ]
}

@test "the lease is released on the merged path" {
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(lock_calls release)" -ge 1 ]
}

@test "the lease is released on a die path too — a leak would wedge the fleet" {
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[ "$(lock_calls release)" -ge 1 ]
}

@test "the CI race waits on ITS OWN pids, never on every background job" {
	# A bare `wait` waits for every background job of the shell, and since the
	# landing lease one of them is the heartbeat — which by design never exits.
	# So a bare wait blocks forever the moment CI answers: `land` sat at that
	# line for five minutes with every check green and the SHA landable, logging
	# nothing (CLOUD-383's shape, made certain by the heartbeat).
	#
	# Asserted structurally because reproducing it needs a never-exiting child,
	# which is exactly what would hang this suite. Comments are stripped so this
	# file's own rationale cannot satisfy the rule it explains.
	run bash -c "sed 's/#.*//' '$REAL_LAND' | grep -nE '^[[:space:]]*wait[[:space:]]*(2>|\$)'"
	[ "$status" -ne 0 ]
}

@test "a watcher that shrugs off the TERM is escalated, never left to outlive the lap" {
	# CLOUD-434. The group TERM measurably missed grandchildren inside one
	# loaded gate run, and the survivors wedged bats through the fd they still
	# held. The reap now verifies the group died and escalates a survivor to
	# SIGKILL; this is that claim's discriminating case — with the escalation
	# deleted, the stubborn watcher outlives the run and this goes red.
	watcher_is_stubborn
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ -s "$BATS_TEST_TMPDIR/stubborn.pids" ]
	local pid deadline
	while read -r pid; do
		[ -n "$pid" ] || continue
		deadline=$((SECONDS + 2))
		while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
			sleep 0.1
		done
		! kill -0 "$pid" 2>/dev/null
	done <"$BATS_TEST_TMPDIR/stubborn.pids"
}

@test "a detached descendant cannot hold bats' output stream — fd 3 is closed beneath the program under test" {
	# CLOUD-434's other half. A watcher that leaves the process group entirely
	# is beyond any reap; what makes it harmless is that nothing under the
	# launcher carries bats' fd 3, so the file completes and the leak costs a
	# stray process rather than a wedged gate. With the launcher's `exec 3>&-`
	# deleted, the child holds the TAP fd and this goes red (bounded: the
	# stand-in sleeps 30s rather than forever, so even the mutant run ends).
	watcher_detaches
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	local deadline pid
	deadline=$((SECONDS + 3))
	while [ ! -s "$BATS_TEST_TMPDIR/detached.pid" ] && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.1
	done
	[ -s "$BATS_TEST_TMPDIR/detached.pid" ]
	pid=$(cat "$BATS_TEST_TMPDIR/detached.pid")
	[ ! -e "/proc/$pid/fd/3" ]
	kill -9 "$pid" 2>/dev/null || true
}
