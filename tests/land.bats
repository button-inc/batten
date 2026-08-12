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
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
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
	# What `gh pr list --head <branch> --state open` returns. Only the resolution
	# cases clear PR and read it; every other case pins the number directly.
	printf '[{"number":150}]' >"$BATS_TEST_TMPDIR/prlist"
	printf '[{"number":150}]' >"$BATS_TEST_TMPDIR/prlist.all"
	: >"$BATS_TEST_TMPDIR/comments"
	: >"$BATS_TEST_TMPDIR/gitlog"
	: >"$BATS_TEST_TMPDIR/misecalls"
	stub_gh
	stub_git
	stub_mise
	pr_state OPEN
	workflow_runs runs.last
}

teardown() {
	# CLOUD-390. The slow-CI and slow-verify levers used to answer after a
	# guessed 30s, and a guessed margin is self-limiting: whatever a case leaked
	# died on its own before the next one started. They now model the wait they
	# are named for — one that does not return — so nothing limits a leak but
	# this. A regressed reap, or a mutant under test that never kills the race's
	# loser, must cost a stray process for one teardown and never a stub that
	# outlives the whole gate run holding a fd.
	#
	# Not hypothetical: main-watch has blocked forever for its own losers since
	# CLOUD-246, and a box mid-way through this change was carrying three of
	# them at 50 minutes old, each with the land that spawned it still parked in
	# `wait`. That is what an unswept never-answering stub looks like, and the
	# two levers below just made two more of them possible.
	#
	# Matched on the per-test stub PATH, not on `mise` or on a task name: bats
	# gives every case its own $BATS_TEST_TMPDIR, so this pattern names a file
	# only this case can have executed. Under the parallel runner a sibling's
	# stub lives at a different tmpdir and cannot match — which is the property
	# tests/land-lock.bats gets for free from serial execution and this file,
	# stubbing a tool every suite runs, has to buy explicitly.
	pkill -f "$BATS_TEST_TMPDIR/bin/mise" 2>/dev/null || true
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
# "gh api -X POST URL" puts the url after the flag, so position is not enough
# (CLOUD-369). Take the first argument that looks like an endpoint instead.
# No backticks here: the heredoc is unquoted, so they would open a command
# substitution in the TEST file rather than quote a word in the stub.
for a in "\$@"; do case "\$a" in repos/*) url="\$a"; break ;; esac; done
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
  # CLOUD-465: the OPEN PR for this branch, and the stub FILTERS because the real
  # endpoint does. Without that a case cannot tell $(--state open) from its
  # absence, and the assertion that $(land) binds the open PR proves nothing —
  # measured, when removing the flag left both cases green. Two bodies: what an
  # open-only query returns, and what an unfiltered one returns for a branch name
  # whose older PRs merged, which is the shape every second landing produces.
  "pr list")
    case "\$all" in
      *"--state open"*) emit "\$(cat "$BATS_TEST_TMPDIR/prlist" 2>/dev/null)" ;;
      *)                emit "\$(cat "$BATS_TEST_TMPDIR/prlist.all" 2>/dev/null)" ;;
    esac ;;
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
      # CLOUD-408: the /fast-forward directive is now POSTed through the API so
      # its comment id — the key the verdict filter matches on — comes back.
      # The rc.comment sentinel makes the POST fail the way a secondary rate
      # limit does. No backticks in here: this heredoc is unquoted, so shfmt
      # reads a backtick pair as command substitution and rewrites it.
      *issues/*/comments*)
        if [ -f "$BATS_TEST_TMPDIR/rc.comment" ]; then
          echo "GraphQL: was submitted too quickly (addComment)" >&2; exit 1
        fi
        echo "\$all" >>"$BATS_TEST_TMPDIR/comments"
        emit '{"id":7}' ;;
      # CLOUD-414: a query that fails writes its error body to STDOUT, which is
      # exactly how a 403 used to reach the verdict as a refusal.
      *actions/workflows/*)
        if [ -f "$BATS_TEST_TMPDIR/rc.runs" ]; then
          emit '{"message":"API rate limit exceeded","status":"403"}'; exit 1
        fi
        emit "\$(nth runs)" ;;
      # CLOUD-369: the runs this lap started, and the cancel that ends them.
      # The url is recorded rather than counted, so a case can assert WHICH run
      # was cancelled and not merely that something was.
      */cancel)              echo "\$url" >>"$BATS_TEST_TMPDIR/cancels" ;;
      # Read from a file so a case can say the head's runs were CANCELLED
      # (CLOUD-470), defaulting to the body every cancel case already relies on
      # — so those rows are untouched and this one is additive.
      *actions/runs?head_sha*)
        if [ -s "$BATS_TEST_TMPDIR/headruns" ]; then emit "\$(cat "$BATS_TEST_TMPDIR/headruns")"
        else emit '{"workflow_runs":[{"id":4242,"status":"in_progress"},{"id":99,"status":"completed"}]}'; fi ;;
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
	echo cafe1234cafe1234 >"$BATS_TEST_TMPDIR/headsha"
	echo ma1nma1nma1nma1n >"$BATS_TEST_TMPDIR/mainsha"
	echo 5peccccc5peccccc >"$BATS_TEST_TMPDIR/specsha"
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_rebase"
	echo 0 >"$BATS_TEST_TMPDIR/rc.reset"
	# 1 by default: the holder's head is NOT already in our history, and the base
	# we bet on has NOT landed. Both are the ordinary readings — a lease is held
	# by someone whose work is still in flight.
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_ancestor"
	cat >"$STUB/git" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/gitlog"
case "\$*" in
  "rev-parse HEAD")              cat "$BATS_TEST_TMPDIR/headsha" ;;
  # Read from a file rather than echoed, because CLOUD-369 made "did main move
  # while this lap waited for the lease" a real question land asks twice in one
  # lap. A constant could not express the one answer that matters.
  "rev-parse origin/main")       cat "$BATS_TEST_TMPDIR/mainsha" ;;
  "rev-parse refs/batten-spec/base") cat "$BATS_TEST_TMPDIR/specsha" ;;
  "rev-parse origin/"*)          cat "$BATS_TEST_TMPDIR/remote_ref" ;;
  "rev-parse --abbrev-ref HEAD") cat "$BATS_TEST_TMPDIR/branch" ;;
  "rev-parse --short"*)          echo abc1234 ;;
  "rev-parse --show-toplevel")   echo "$BATS_TEST_TMPDIR" ;;
  "fetch"*)                      exit "\$(cat "$BATS_TEST_TMPDIR/rc.fetch")" ;;
  # TWO DIFFERENT ANCESTRY QUESTIONS, and one file could not answer both. The
  # lap asks "am I a descendant of main"; CLOUD-369's speculation asks "is the
  # holder's head already in my history" and "did the base I bet on land". A
  # single rc made the second answer yes by accident, and the speculation
  # silently returned early — which the suite then reported as the mechanism
  # never having run.
  "merge-base --is-ancestor origin/main HEAD") exit "\$(cat "$BATS_TEST_TMPDIR/rc.linear")" ;;
  "merge-base"*)                 exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_ancestor")" ;;
  "rebase --abort")              exit 0 ;;
  # The SPECULATIVE rebase is a different event from the lap's rebase onto main
  # (CLOUD-369) and fails differently: a conflict here is information about a
  # base that may never land, so it falls back rather than stopping.
  "rebase origin/main")          exit "\$(cat "$BATS_TEST_TMPDIR/rc.rebase")" ;;
  "rebase"*)                     exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_rebase")" ;;
  "reset -q --hard"*)            exit "\$(cat "$BATS_TEST_TMPDIR/rc.reset")" ;;
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
    # CLOUD-434's detach lever lives HERE, not in the raced watcher: a group
    # kill races the watcher's first write, and CI measurably won that race
    # (not ok 485) while a fast local box lost it — the CLOUD-426 class,
    # rebuilt by accident. The verify stub runs to completion in the fd case,
    # so the spawn is kill-race-free; the fd property is position-independent,
    # since any descendant of the launcher demonstrates it. setsid --fork is
    # load-bearing too: bare setsid execs IN-PROCESS when the caller is no
    # group leader, which kept the "detached" child killable.
    if [ -f "$BATS_TEST_TMPDIR/detach" ] && [ ! -f "$BATS_TEST_TMPDIR/detached.pid" ]; then
      setsid --fork bash -c "echo \\\$\\\$ >'$BATS_TEST_TMPDIR/detached.pid'; sleep 30" >/dev/null 2>&1
      # CLOUD-457. setsid returns as soon as the fork is made; it promises
      # nothing about the child having been SCHEDULED, and until the child runs
      # its first command the pid file does not exist. The case downstream used
      # to allow three seconds for that from the test body and read a loaded
      # box's scheduling delay as "the descendant was never detached" — a red
      # row for a launcher that did exactly what it claims.
      #
      # The waiting belongs HERE, next to the fork, and not in the body: since
      # CLOUD-434 moved the spawn into this stub, run "\$LAND" has already
      # returned by the time the body runs, so a body-side loop conditioned on
      # "the spawning land has exited" is true on entry every single time and
      # waits for nothing. An attempt cap, never a clock: 200 polls of 0.05s is
      # a bound on tries, and if the child still has not published, the stub
      # SAYS so through a marker rather than leaving the body to infer it from
      # an empty file it cannot tell from a launcher that never spawned.
      tries=0
      while [ ! -s "$BATS_TEST_TMPDIR/detached.pid" ] && [ "\$tries" -lt 200 ]; do
        sleep 0.05
        tries=\$((tries + 1))
      done
      [ -s "$BATS_TEST_TMPDIR/detached.pid" ] || : >"$BATS_TEST_TMPDIR/detach.unscheduled"
    fi
    # CLOUD-423's lever, consumed BEFORE the wait: a verify killed mid-gate
    # must not slow the lap that retries it, and the kill landing during the
    # wait is exactly the abort under test — the receipt line is never
    # reached, so the abort-leaves-no-receipt property is observed for real.
    #
    # CLOUD-390: the wait does not end on its own. It used to be a 30s sleep —
    # a guess at how long a real gate outlives its race — and a self-ending
    # stub is a way for these rows to reach green without land having killed
    # anything, which is the one thing they are about. Same reasoning as the
    # ci-wait lever above; the two are the same defect written twice.
    if [ -f "$BATS_TEST_TMPDIR/verify.slow" ]; then
      rm -f "$BATS_TEST_TMPDIR/verify.slow"
      while :; do sleep 1; done
    fi
    : >"$BATS_TEST_TMPDIR/receipt"; exit 0 ;;
  verified)
    if [ ! -f "$BATS_TEST_TMPDIR/receipt" ]; then
      # 'verified' is a gate: a missing receipt is a failure and it SAYS so.
      # Modelling that is what makes the quiet-success property meaningful.
      # (Quoted plainly on purpose — this heredoc is unquoted, so a dollar-
      # paren here is a live substitution that ran a nonexistent command at
      # setup time and salted every failure dump with its stderr.)
      echo "::error:: HEAD is NOT verified — no verify receipt for this commit." >&2
      exit 1
    fi
    exit 0 ;;
  # CLOUD-323's stop. Passes by default; a case that wants the refusal
  # writes rc.mise.deferral-check, the same lever every other task uses.
  deferral-check) exit 0 ;;
  ci-wait)
    # Every watcher records itself, so the trap-reap case can ask "who did a
    # lap spawn" and assert each one is gone (CLOUD-434's trap gap).
    echo "\$\$" >>"$BATS_TEST_TMPDIR/watch.pids"
    # CLOUD-390: "CI is still running" is a wait that does not return, not one
    # that returns after a guessed 30s, and this is the shape main-watch
    # already uses for its own loser further down. The guess was not merely
    # imprecise, it was a SECOND way for a reap row to go green: a stub that
    # terminates itself satisfies "the watcher is gone" without anything having
    # reaped it, so those rows held only while 30 stayed larger than the settle
    # windows they poll with (4s below). Two guessed numbers that must stay
    # ordered, with nothing checking the order. Now the only exit is land's
    # kill, which is the claim the rows are about.
    #
    # Consumed on the first slow call, exactly as verify.slow is. The lever
    # says "lose THIS lap", and a landing that laps must reach a lap whose CI
    # does answer or it never merges: left standing, it wedged lap 2 of the two
    # race rows forever. Those rows used to reach green by sitting out the full
    # sleep on lap 2 — 31.5s for "main moving mid-wait", measured before this
    # change and 1.5s after it.
    if [ -f "$BATS_TEST_TMPDIR/ci-wait.slow" ]; then
      rm -f "$BATS_TEST_TMPDIR/ci-wait.slow"
      while :; do sleep 1; done
    fi
    exit 0 ;;
  land-lock)
    # Per-verb levers (CLOUD-369). The whole-task \`rc.mise.land-lock\` file
    # still works through the generic check above; this is what a case needs to
    # say "acquire loses but reserve wins", which is the successor's whole path.
    rcv="$BATS_TEST_TMPDIR/rc.mise.land-lock.\$3"
    # MAIN MOVES DURING A WAIT, AND THE LAP IT MOVES ON MATTERS. A bet is placed
    # during the FIRST wait, so moving trunk before that one would make the bet
    # read as already-decided and no speculation would ever be settled. The
    # lever therefore fires from the second acquire on: bet first, then the
    # world moves under it, which is the sequence the unwind exists for.
    if [ "\$3" = acquire ]; then
      n=\$(cat "$BATS_TEST_TMPDIR/acquire.calls" 2>/dev/null || echo 0)
      n=\$((n + 1)); echo "\$n" >"$BATS_TEST_TMPDIR/acquire.calls"
      after=\$(cat "$BATS_TEST_TMPDIR/main_moves_after" 2>/dev/null || echo 1)
      if [ -f "$BATS_TEST_TMPDIR/main_moves_in_wait" ] && [ "\$n" -ge "\$after" ]; then
        # A DISTINCT sha per acquire, not one fixed value. "main is moving
        # faster than a lap takes" is the condition under test, and a lever that
        # moved trunk once left the next lap's re-confirmation passing — so the
        # lap proceeded to a poll that, with no terminal PR state, never
        # returned. Measured as a hung case that leaked a watcher per run.
        echo "\$(cat "$BATS_TEST_TMPDIR/main_moves_in_wait")\$n" >"$BATS_TEST_TMPDIR/mainsha"
      fi
    fi
    [ ! -f "\$rcv" ] || exit "\$(cat "\$rcv")"
    if [ "\$3" = peek ]; then
      f="$BATS_TEST_TMPDIR/lease.\$4"
      [ ! -f "\$f" ] || cat "\$f"
    fi
    [ "\$3" != held ] || exit 0
    exit 0 ;;
  main-watch)
    echo "\$\$" >>"$BATS_TEST_TMPDIR/watch.pids"
    # CLOUD-434's stubborn lever. A stubborn watcher ignores the TERM, so only
    # the escalated reap can end it. (The detach lever spawns from the verify
    # stub instead — see there for the measured kill-race that moved it.)
    if [ -f "$BATS_TEST_TMPDIR/stubborn" ]; then
      trap '' TERM
      echo "\$\$" >>"$BATS_TEST_TMPDIR/stubborn.pids"
    fi
    # THE VERIFY RACE IS SYNCHRONISED, NOT HOPED FOR (CLOUD-426's class, in the
    # case CLOUD-423 added). Whichever way this watcher is about to answer, it
    # answers only once the verify it races has registered itself — otherwise
    # \`land\` group-kills a verify child that has not yet appended its call, the
    # lap that follows counts one verify instead of two, and the case fails on a
    # loaded box while passing on an idle one. Measured: it went red inside a
    # full parallel gate and passed standalone. Bounded, and it waits for a real
    # event rather than a guessed interval.
    if [ "\${LAND_RACE:-}" = verify ]; then
      for _ in \$(seq 200); do
        grep -q '^run verify\$' "$BATS_TEST_TMPDIR/misecalls" && break
        sleep 0.05
      done
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
# The supersession set (CLOUD-363): the landing SHA's runs were killed by a
# concurrent event, so nothing on this head judged anything.
head_is_all_cancelled() { head_checks '{"check_runs":[{"name":"ci","status":"completed","conclusion":"cancelled"}]}'; }
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
# Alive means RUNNING, not merely unreaped: a SIGKILLed process lingers as a
# zombie until its (dead) parent's reaper gets to it, `kill -0` answers true
# for zombies, and under a loaded gate the reap can outlast any fixed settle —
# measured as a flake of the escalation case inside a full parallel verify.
# The state field is read past the comm's closing paren, since comm may
# legally contain the space that would break a naive field split.
alive_not_zombie() {
	local st
	st=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1) || return 1
	[ -n "$st" ] && [ "$st" != "Z" ]
}
ready_calls() { cat "$BATS_TEST_TMPDIR/ready"; }
# CLOUD-470: the head's own runs read as cancelled, which is the fingerprint of a
# run the lease precondition declined rather than one that failed.
head_runs_cancelled() {
	printf '{"workflow_runs":[{"id":4242,"status":"completed","conclusion":"cancelled"}]}' \
		>"$BATS_TEST_TMPDIR/headruns"
}
cancels() { cat "$BATS_TEST_TMPDIR/cancels" 2>/dev/null || true; }
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
	# The 4th argument is `display_title`, defaulting to the KEY this lap mints
	# (CLOUD-409). Without a default every existing refusal row would silently
	# stop matching the new filter and the suite would go red for the wrong
	# reason; with it, a row that wants a STRANGER's refusal says so explicitly.
	local title="${4:-fast-forward #150 @7}"
	if [ -z "$conclusion" ]; then
		printf '{"workflow_runs":[]}' >"$BATS_TEST_TMPDIR/$file"
	else
		printf '{"workflow_runs":[{"created_at":"%s","status":"completed","conclusion":"%s","display_title":"%s"}]}' \
			"$created" "$conclusion" "$title" >"$BATS_TEST_TMPDIR/$file"
	fi
}

# A refusal belonging to some other PR's lap, inside our own SINCE window.
sibling_refuses() { workflow_runs "$1" failure 2099-01-01T00:00:00Z "fast-forward #999 @4242"; }
comment_fails() { : >"$BATS_TEST_TMPDIR/rc.comment"; }
runs_query_403() { : >"$BATS_TEST_TMPDIR/rc.runs"; }

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

@test "a cancelled run is the bot failing to DECIDE, not a refusal" {
	# REWRITTEN, and the old row pinned exactly the behaviour CLOUD-413 says is
	# wrong. A cancelled run judged nothing; calling it a refusal narrated "main
	# moved under the branch" and bought a full lap — measured across 24 laps of
	# one landing where several "refusals" were the bot's own rate limit and
	# `main` had not moved at all.
	pr_state OPEN MERGED
	workflow_runs runs.1 cancelled
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no readable answer"* ]]
	[[ "$output" != *"refused (cancelled)"* ]]
	[[ "$output" != *"main moved under"* ]]
}

@test "a SIBLING PR's refusal is not this lap's verdict (CLOUD-409)" {
	# At the measured cadence the SINCE window held 243 strangers' refusals, any
	# of which this lap would have read as its own — which is how "the bot is
	# silent or slow" was inferred while the bot answered every attempt inside
	# 23 seconds. The run below is keyed to PR #999; ours is #150.
	pr_state OPEN OPEN MERGED
	sibling_refuses runs.1
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" != *"the fast-forward bot refused"* ]]
	[ "$(comments)" -eq 1 ]
}

@test "a keyed refusal IS still read — the filter did not stop reading" {
	# The negative control for the row above. A fix that keyed too tightly would
	# never see a refusal again and would reintroduce CLOUD-235's hang.
	pr_state OPEN MERGED
	workflow_runs runs.1 failure
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the fast-forward bot refused (failure)"* ]]
	[ "$(comments)" -eq 2 ]
}

@test "a /fast-forward the API refused is never reported as posted (CLOUD-408)" {
	# Measured on PR #330: GitHub answered the secondary rate limit, `gh` exited
	# non-zero, nothing read it, and land printed "commented /fast-forward …
	# waiting for the merge" over a comment that did not exist — then blocked
	# waiting for a merge nothing had been asked to perform.
	comment_fails
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" != *"commented /fast-forward on #150"* ]]
	[[ "$output" == *"could not ask #150 to fast-forward"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a 403 from the runs query is not an answer (CLOUD-414)" {
	# `gh` writes the error body to STDOUT, so the unfiltered body reached the
	# verdict where the test was `[ -z ]` — any non-empty string was a refusal,
	# and a transport error was indistinguishable from one. The bound is a COUNT
	# of unreadable answers, never a clock on the poll.
	runs_query_403
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" != *"refused"* ]]
	[[ "$output" == *"no readable answer"* ]]
	[[ "$output" == *"gh api rate_limit"* ]]
}

@test "an unreadable answer re-asks without buying a CI run" {
	# The whole reason an unknown re-asks rather than stopping: on an unmoved
	# `main` the lap is free — the verify receipt still keys to this HEAD, the
	# head already graded so neither ready fires, and the push moves nothing.
	# The head is already GRADED, which is the precondition the property rests
	# on and which the default fixture does not create: an empty check-runs
	# reading makes `graded_runs` answer 0, and 0 is the branch that fires the
	# ready. Without this the row would be asserting the free-lap claim against
	# a fixture that cannot exhibit it.
	head_checks '{"check_runs":[{"status":"completed","conclusion":"success","name":"ci","started_at":"2026-01-01T00:00:00Z","id":1}]}'
	runs_query_403
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=2 run "$LAND"
	[ "$status" -eq 1 ]
	# Nothing is bought across either pass: the head already carries a graded
	# run so neither the ready nor the `--undo` re-fire can fire, and one verify
	# because the receipt still keys to this unchanged HEAD.
	[ "$(grep -c '^ready$' "$BATS_TEST_TMPDIR/calls")" -eq 0 ]
	[ "$(grep -c '^run verify$' "$BATS_TEST_TMPDIR/misecalls")" -eq 1 ]
}

@test "the fast-forward verdict is KEYED, not merely windowed" {
	# The structural sensor, in the shape of the no-wall-clock row below: the
	# filter is only sound while the workflow keeps minting the key, and nothing
	# else in the tree couples the two files.
	run grep -c 'per_page=20' "$REAL_LAND"
	[ "$output" -eq 0 ]
	run grep -c 'display_title' "$REAL_LAND"
	[ "$output" -ge 1 ]
	run grep -c '^run-name:' "$BATS_TEST_DIRNAME/../.github/workflows/fast-forward.yml"
	[ "$output" -eq 1 ]
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
	[ "$status" -eq 5 ]
	[[ "$output" == *"still not linear after 3 laps"* ]]
	[ "$(verify_calls)" -eq 3 ]
	[ "$(comments)" -eq 0 ]
}

@test "CLOUD-399: the two exhaustions are told apart by CODE, not by prose" {
	# The pair is the point. A saturated fleet ("wait, and land later — nothing
	# is wrong") and a runaway branch ("main moves faster than a lap takes —
	# look") both ended in `exit 1`, so a caller keying on a status could not
	# tell "retry me later" from "I am broken". Swapping the two verdicts must
	# red this case; a single-code assertion would pass on the swap.
	#
	# The wait side also asserts the COST, which is the whole reason the two are
	# priced differently: a branch that never won a turn must have bought no
	# matrix at all — no ready, no push, no comment.
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	saturated="$status"
	[ "$saturated" -eq 4 ]
	[[ "$output" == *"fleet is saturated"* ]]
	[ "$(call_order)" = "" ]
	[ "$(comments)" -eq 0 ]

	setup

	echo 2 >"$BATS_TEST_TMPDIR/rc.mise.verify"
	LAND_MAX_LAPS=1 run "$LAND"
	runaway="$status"
	[ "$runaway" -eq 5 ]
	[[ "$output" == *"moving faster than a lap takes"* ]]

	# The property itself, stated once: distinguishable, and neither is the
	# generic stop that every other `die` in this task uses.
	[ "$saturated" -ne "$runaway" ]
	[ "$saturated" -ne 1 ]
	[ "$runaway" -ne 1 ]
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
	# The anti-regression half of the CLOUD-470 pair: a GENUINE red must keep
	# today's message. A change that printed the rebase remedy unconditionally
	# would pass the two cases below and misdirect every real CI failure.
	[[ "$output" != *"CANCELLED"* ]]
}

@test "a run CI DECLINED is a stop, not a red — the agent is told to rebase" {
	# CLOUD-470. `ci-lease-precondition` stops an unauthorised head by cancelling
	# its run, and `final` reds under `always()` — so the wait returns non-zero
	# with nothing broken. Measured: 11 of 13 open PRs carried a `land` predating
	# the lease, so every one of those agents was sent to debug a disagreement
	# that did not exist. Nothing local can fix it; the remedy is a rebase.
	head_runs_cancelled
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CANCELLED"* ]]
	[[ "$output" == *"git rebase origin/main"* ]]
	[[ "$output" != *"verify and CI disagree"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a verdict that could not be READ is not a red one" {
	# `ci-wait` exit 2 is "could not look" (its own contract), and the guard was
	# `!= 0`, so a verdict nobody obtained was reported as a red run on a
	# verified branch — sending the agent to reconcile a disagreement that was
	# never observed.
	task_fails_once_with ci-wait 2
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not read CI's verdict"* ]]
	[[ "$output" != *"CI is red"* ]]
}

@test "an unset required roster stops rather than readying (CLOUD-467)" {
	# `graded_runs` answered 0 on an unset roster, and 0 is the branch that FIRES
	# THE READY THAT STARTS CI — so the one input this task cannot compute became
	# the answer that spends a full matrix. `checks-green` guards the same
	# variable eight lines away in the file it is paired with.
	CI_REQUIRED_CHECKS= run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI_REQUIRED_CHECKS is unset"* ]]
	[ "$(ready_calls)" = "" ]
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
	[ "$status" -eq 5 ]
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

@test "a branch with no OPEN PR has nothing to land" {
	# `gh pr list --state open` on such a branch prints nothing, so the lookup
	# comes back empty — an empty body through the real `--jq` is what the stub
	# reproduces.
	rm -f "$BATS_TEST_TMPDIR"/state.[0-9]*
	: >"$BATS_TEST_TMPDIR/state.last"
	printf '[]' >"$BATS_TEST_TMPDIR/prlist"
	printf '[{"number":366}]' >"$BATS_TEST_TMPDIR/prlist.all"
	PR= run timeout -k 1 15 "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing to land"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "THE MERGED-NAME CASE: a branch whose old PR merged binds the OPEN one (CLOUD-465)" {
	# The default shape, not an edge case. Trunk-based development deletes the
	# branch on merge, and the session harness pins an agent to one branch name
	# for its whole engagement — so the second landing of any session recycles a
	# name whose previous PR is merged. A bare `gh pr view` answers with that
	# merged PR, and `land` then drives a pull request that is already finished.
	printf '[{"number":368}]' >"$BATS_TEST_TMPDIR/prlist"
	printf '[{"number":366},{"number":368}]' >"$BATS_TEST_TMPDIR/prlist.all"
	pr_state MERGED
	PR= run timeout -k 1 15 "$LAND"
	[ "$status" -eq 0 ]
	# Every comment and read went to the open PR, never to the merged one.
	[[ "$(cat "$BATS_TEST_TMPDIR/comments")" == *"368"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/comments")" != *"366"* ]]
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

# --- CLOUD-458: the tap closes on every non-merged exit, not only on red ------
#
# What `checks-green` answers for the head when a landing stops. Absent means
# GREEN, since the mise stub's default is exit 0 — so every case above that ends
# without merging asserts the leave-it-ready side by construction, which is why
# none of them needed changing.
head_verdict() { echo "$1" >"$BATS_TEST_TMPDIR/rc.mise.checks-green"; }

@test "a landing interrupted on an ungraded head re-drafts, not only a red one" {
	# The measured leak: `land` readied, something other than red ended the run,
	# and the PR stayed ready for good — so every later push bought a full
	# matrix with no landing attempt in progress at all.
	head_verdict 3
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$(ready_calls)" == *"--undo"* ]]
	[[ "$output" == *"stopped without merging"* ]]
}

@test "the same interruption over a green head leaves it ready" {
	# The other direction, and what makes the guard load-bearing rather than
	# decorative: the pre-push ready fires only on a head with NO graded run, so
	# re-drafting a green head strands it — and readying it again would buy a
	# whole matrix to get back where it already was. Green resumes for free.
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "a head whose verdict could not be read is left ready, never stranded" {
	# `checks-green` exit 2 is "I could not look", which is not evidence of
	# anything. Acting on it would strand a green head on a reading we failed to
	# take; the leak it leaves open costs a run, and the strand costs a wedge.
	head_verdict 2
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "a landing that merges leaves the PR alone" {
	# The one exit with no tap to close. The verdict lever is set to the value
	# that WOULD re-draft, so this asserts the `landed` flag rather than the
	# absence of an opportunity.
	pr_state MERGED
	head_verdict 3
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "a refused second land does not re-draft the live one's PR" {
	# A land that never took the singleton owns neither the lease nor the PR.
	# Its EXIT trap already knows not to release the lock; this is the same
	# discipline applied to the other side effect.
	task_fails singleton
	head_verdict 3
	run "$LAND"
	[ "$status" -ne 0 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
}

@test "a re-draft that cannot happen does not change the exit code" {
	# Cleanup that can fail an exit path is worse than the leak it closes: the
	# status must still be the rebase conflict's, not the re-draft's.
	head_verdict 3
	undo_fails
	not_linear
	fails rebase
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" != *"re-drafted"* ]]
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

@test "a ready PR whose head carries only cancelled runs has its ready re-fired" {
	# THE WEDGE (CLOUD-363), measured on #293. `land` readied and then
	# force-pushed; both events reached the same `concurrency: ci-<ref>` group two
	# seconds apart and the run on the SHA that would land was the one cancelled.
	# `graded_runs` counted `cancelled` as an answer, so this block did not fire —
	# and with HEAD unchanged, the push moving nothing and the verify receipt
	# still valid, re-running `land` re-read the identical stale set forever. Two
	# consecutive invocations died on it; the only escape was a hand-minted SHA,
	# which is a manual step outside the loop this task exists to drive.
	head_is_all_cancelled
	push_moves_nothing
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$(ready_calls)" == *"--undo"* ]]
	[[ "$output" == *"re-fired the ready"* ]]
}

@test "the re-drafted PR a cancelled set left behind is readied, not stuck" {
	# The state `land` actually leaves after reporting red: `redraft` closed the
	# tap, so the next invocation meets a DRAFT whose head carries the cancelled
	# set. That is the entry point recovery has to work from, and it takes the
	# other ready block — the pre-push one — so `--undo` is neither needed nor
	# spent (CLOUD-255 still holds on this path).
	is_draft
	head_is_all_cancelled
	push_moves_nothing
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(grep -c . "$BATS_TEST_TMPDIR/ready")" -eq 1 ]
	[[ "$(ready_calls)" != *"--undo"* ]]
	[[ "$output" == *"readied #150 before pushing"* ]]
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
	# `|| rc=$?` because a bats body aborts on a non-zero command, and a timeout
	# is the result this case is asserting rather than a failure of it.
	# `run_timeout` is tests/helpers.bash's shim: stock macOS ships no `timeout`
	# (CLOUD-282), and this case is the one that most needs it to exist.
	run_timeout -k 1 5 "$LAND" >"$out" 2>&1 || rc=$?
	# 124 OR 137 (CLOUD-464). Both are `timeout` saying "the command did not
	# finish", which is the whole property here; what separates them is machine
	# load, not behaviour. GNU `timeout` returns 124 when the process dies from
	# the TERM it sent and 137 when `-k` had to escalate to KILL because TERM was
	# not serviced within the grace second — and `land` runs `set -m`, installs
	# an EXIT trap and reaps two watcher process groups, so how long that takes
	# depends on what else is running. Asserting 124 alone made a contended box
	# red and an idle one green, which is CLOUD-426's shape in its sibling case.
	#
	# Not a loosening: a `land` that ended the lap on its own exits with its own
	# status, so neither code can appear and a broken poll still fails this.
	[ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]
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
	#
	# BOTH SPELLINGS ARE COUNTED (CLOUD-399). The two exhaustions now carry their
	# own exit codes through `die_with`, and counting only `die "` would have let
	# this sensor read 18-of-20 as "two stops removed" — or, worse, let a future
	# `die_with` stop be added completely uncounted. That is the exact blindness
	# this assertion exists to prevent, reintroduced by the change that split the
	# helper. `die_with` is matched on its code argument, which every call carries.
	stops=$(grep -cE 'die "|die_with "?\$?[A-Za-z_]' "$REAL_LAND")
	[ "$stops" -eq 20 ] || {
		echo "land has $stops stopping conditions; this suite covers 20."
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
	# 15 since CLOUD-428: one land per clone. Exercised by the singleton case
	# below, and this counter is why that stop goes through `die` rather than a
	# bare `exit` — an exit nothing counts is an exit nothing tests.
	laps=$(grep -cE '^[[:space:]]*continue$' "$REAL_LAND")
	# 11 since CLOUD-369: the warm queue adds four — the lease was lost (now the
	# path that speculates and may reserve), the successor pushed and lapped, the
	# successor is already in flight for this head, and the winner found main had
	# moved while it waited. Each is exercised below.
	[ "$laps" -eq 13 ] || {
		echo "land has $laps lap-ending continues; this suite covers 13."
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

lock_calls() { grep -c "^run land-lock $1\b" "$BATS_TEST_TMPDIR/misecalls" || true; }

@test "a second land in this clone is refused before anything is spent (CLOUD-428)" {
	# The landing lease cannot answer this — it is re-entrant per clone by
	# design, so two lands in one checkout both acquire and the second heartbeat
	# renews the first's lease. Measured 2026-08-12: three concurrent lands on
	# one branch for ~30 minutes.
	#
	# The refusal has to land BEFORE any spend, so the assertions below are
	# about what did NOT happen: no ready, no push, no lease taken.
	task_fails singleton
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"refusing to start a second land in this clone"* ]]
	[ "$(call_order)" = "" ]
	[ "$(ready_calls)" = "" ]
	[ "$(lock_calls acquire)" -eq 0 ]
}

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
	[ "$status" -eq 4 ]
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
	[ "$status" -eq 5 ]
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
		deadline=$((SECONDS + 4))
		while alive_not_zombie "$pid" && [ "$SECONDS" -lt "$deadline" ]; do
			sleep 0.1
		done
		! alive_not_zombie "$pid"
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
	local pid
	# CLOUD-457. The stand-in is spawned inside the verify stub and waited for
	# there, where the fork happens — by the time this line runs the land has
	# already exited, so there is nothing left here to poll against. What the
	# body reads is the stub's verdict: the marker means the child was never
	# scheduled, which is a statement about the BOX, not about the launcher.
	#
	# Skipping on it erases no coverage. The mutant this row catches is the
	# launcher's `exec 3>&-` being deleted, and that mutant still spawns the
	# child and still publishes its pid — the child is identical either way and
	# differs only in the fd it inherits. So the mutant reaches the /proc
	# assertion below, which is never skipped, and dies there. A skip here can
	# only ever swallow "the scheduler was too busy to start a process", which
	# no mutant of land can cause and no assertion of this row is about.
	if [ -f "$BATS_TEST_TMPDIR/detach.unscheduled" ]; then
		skip "CLOUD-457: the detached stand-in was never scheduled; nothing to read an fd from"
	fi
	[ -s "$BATS_TEST_TMPDIR/detached.pid" ]
	pid=$(cat "$BATS_TEST_TMPDIR/detached.pid")
	[ ! -e "/proc/$pid/fd/3" ]
	kill -9 "$pid" 2>/dev/null || true
}

@test "a land killed mid-race takes its watchers with it — the trap reaps the races too" {
	# CLOUD-434's review finding, closed: dying THROUGH the exit trap used to
	# reap only the heartbeat, and a TERMed land orphaned a live gh-polling
	# ci-wait for a measured 10 minutes. The live race pids are globals the
	# trap reaps, cleared after every inline reap — so this case kills a land
	# mid-race and demands every watcher the lap spawned be gone once the trap
	# has run. With reap_races neutered, the slow ci-wait stub survives and
	# this goes red.
	ci_is_slow
	pr_state OPEN
	"$LAND" >"$BATS_TEST_TMPDIR/late.out" 2>&1 3>&- &
	land_pid=$!
	local deadline pid
	deadline=$((SECONDS + 10))
	while [ ! -s "$BATS_TEST_TMPDIR/watch.pids" ] && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.2
	done
	[ -s "$BATS_TEST_TMPDIR/watch.pids" ]
	# Let the race pair finish spawning before the kill, so the trap has both
	# groups to reap rather than a half-started race.
	sleep 0.5
	kill -TERM "$land_pid"
	deadline=$((SECONDS + 5))
	while alive_not_zombie "$land_pid" && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.1
	done
	! alive_not_zombie "$land_pid"
	while read -r pid; do
		[ -n "$pid" ] || continue
		deadline=$((SECONDS + 4))
		while alive_not_zombie "$pid" && [ "$SECONDS" -lt "$deadline" ]; do
			sleep 0.1
		done
		! alive_not_zombie "$pid"
	done <"$BATS_TEST_TMPDIR/watch.pids"
}

# --- graded_runs judges the latest run too (CLOUD-436) -----------------------
#
# `graded_runs` asks "does this SHA carry an answer yet", and it decides whether
# the ready that STARTS CI is fired. It shares $CI_REQUIRED_CHECKS with
# `checks-green` so the two cannot disagree about what is required; they now
# share the latest-per-name rule for the same reason. A draft-created head keeps
# its `opened`-event skip set forever, so counting a superseded run answers for
# a head that has no answer — and the ready never fires.

head_is_graded_then_skipped() {
	head_checks '{"check_runs":[
		{"name":"ci","status":"completed","conclusion":"success","started_at":"2026-08-12T01:00:00Z","id":1},
		{"name":"ci","status":"completed","conclusion":"skipped","started_at":"2026-08-12T02:00:00Z","id":2}]}'
}

head_is_skipped_then_graded() {
	head_checks '{"check_runs":[
		{"name":"ci","status":"completed","conclusion":"skipped","started_at":"2026-08-12T01:00:00Z","id":1},
		{"name":"ci","status":"completed","conclusion":"success","started_at":"2026-08-12T02:00:00Z","id":2}]}'
}

@test "a head whose LATEST required run is a skip has no answer, so the ready is fired" {
	# The discriminating case: without the dedup the superseded success is
	# counted, the head reads as answered, and the one event that starts CI
	# never happens.
	is_draft
	head_is_graded_then_skipped
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ -n "$(ready_calls)" ]
}

@test "a skip its own re-run superseded is an answer, so nothing buys a second run" {
	# The residue shape that wedged #342 and #345, from the other side: the
	# graded run is current, so this head must not spend another matrix.
	is_draft
	head_is_skipped_then_graded
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ -z "$(ready_calls)" ]
}

@test "a run main moved under is CANCELLED, not left to bill for an answer nobody reads" {
	# CLOUD-369. The lap already ends early here (CLOUD-240's race), but ending
	# the lap does not end the RUN: only the next push supersedes it, and with
	# the re-priced lease budgets that push can be many whole waits away. So a
	# doomed four-job matrix bills the whole time.
	#
	# CLOUD-240's refusal is scoped rather than absolute — "supersede your own
	# runs, never someone else's" — and this reaches only runs on this lap's own
	# head sha, which no other branch has.
	ci_is_slow
	main_moves_on_lap 1
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"cancelled run 4242"* ]]
	# The in-progress run, and only it: a completed run has nothing to cancel
	# and asking would be a wasted call.
	[[ "$(cancels)" == *"/4242/cancel"* ]]
	[[ "$(cancels)" != *"/99/cancel"* ]]
}

@test "a lap that CI answered cancels nothing — only a voided run is void" {
	# The discriminating half. Cancelling on any lap ending would reach runs
	# about to deliver a usable verdict, which inverts the economy: a green run
	# is the one thing worth paying out.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ -z "$(cancels)" ]
}

# --- speculative linearization and the admitted successor (CLOUD-369) --------
#
# The lease bounds confirming runs at one, which is right for cost and wrong for
# latency: after every merge the queue is empty and the next branch starts cold.
# Two mechanisms close that window, and the cases below pin the property that
# makes each SAFE rather than merely fast — a speculation that cannot be pushed
# when the bet loses, and a successor slot that exactly one waiter can hold.

spec_head() { echo "$1" >"$BATS_TEST_TMPDIR/lease.branch"; }
lease_lost() { echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.acquire"; }

@test "a waiter linearizes onto the HOLDER's head, not onto the main it is replacing" {
	# Rebasing onto origin/main warms nothing: the holder is about to replace
	# that commit, so the waiter is stale again the moment it wins. The main
	# worth linearizing against is the one about to EXIST.
	lease_lost
	spec_head holder-branch
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	grep -q '^fetch -q origin +refs/heads/holder-branch:refs/batten-spec/base$' "$BATS_TEST_TMPDIR/gitlog"
	grep -q '^rebase 5peccccc5peccccc$' "$BATS_TEST_TMPDIR/gitlog"
	[[ "$output" == *"the main that is about to exist"* ]]
}

@test "a lease naming no head leaves the branch linearized on main, and says nothing" {
	# Every lease minted before this change is exactly this, so during rollout
	# the row is not an edge case — it is every lease.
	lease_lost
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" != *"speculatively linearized"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/gitlog")" != *batten-spec* ]]
}

@test "A CONFLICTING SPECULATION FALLS BACK — it is information, not a stop" {
	# The conflict is real and arrives when that branch lands. But it is a
	# conflict against a base that may never exist, so resolving it now would be
	# resolving it against nothing, and DYING on it would stop a lap that has
	# spent nothing and done nothing wrong.
	lease_lost
	spec_head holder-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_rebase"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"conflicts with this branch; not speculating"* ]]
	# It ends on the wait backstop — the ordinary saturation signal — never on
	# the rebase-conflict stop, which is reserved for the one real decision.
	[[ "$output" == *"never won the landing lease"* ]]
	[[ "$output" != *"resolve it and run land again"* ]]
	grep -q '^rebase --abort$' "$BATS_TEST_TMPDIR/gitlog"
}

@test "THE BET CANNOT BE PUSHED WHEN IT LOSES: a stale speculation is unwound first" {
	# The hazard that makes this whole mechanism dangerous if done naively. A
	# speculative rebase puts ANOTHER branch's unlanded commits into this
	# branch's history; fast-forwarding from there would land somebody else's
	# unmerged work as a side effect of ours. `origin/main --is-ancestor HEAD`
	# does not catch it — the speculated base is itself a descendant of main.
	lease_lost
	spec_head holder-branch
	pr_state MERGED
	# main moves to something that is NOT the speculated base: the bet lost.
	# From the second acquire on — the bet is placed during the first wait, and
	# a world that moved before it was placed would never settle anything.
	echo 0ther0ther0ther0 >"$BATS_TEST_TMPDIR/main_moves_in_wait"
	echo 2 >"$BATS_TEST_TMPDIR/main_moves_after"
	# Not admitted, so nothing is published and the assertion below is about the
	# speculative state alone rather than about the successor path.
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"did not land; unwinding"* ]]
	grep -q '^reset -q --hard cafe1234cafe1234$' "$BATS_TEST_TMPDIR/gitlog"
	# Nothing was published from the speculative state.
	[ "$(call_order)" = "" ]
}

@test "an unwind the tree refuses is a stop, not a lap onto an unknown HEAD" {
	lease_lost
	spec_head holder-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.reset"
	echo 0ther0ther0ther0 >"$BATS_TEST_TMPDIR/main_moves_in_wait"
	echo 2 >"$BATS_TEST_TMPDIR/main_moves_after"
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not unwind the speculative rebase"* ]]
	[ "$(call_order)" = "" ]
}

@test "THE SECOND MATRIX: an admitted successor readies and pushes without the lease" {
	# The saving. Its run overlaps the holder's merge instead of starting cold
	# after it, which is the ~8 minutes of idle main this closes.
	lease_lost
	spec_head holder-branch
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"admitted as the successor"* ]]
	[[ "$output" == *"overlaps the merge in flight"* ]]
	# Readied and pushed — but never commented: the fast-forward needs the lease,
	# and asking for a merge without holding it is the collision the lease exists
	# to prevent.
	[[ "$(call_order)" == "ready push"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "A WAITER THAT IS NOT ADMITTED STAYS IN DRAFT — this is what bounds the cost" {
	# The negative that gives the case above its meaning. Without it, "every
	# waiter readies" would pass the test above and spend a matrix per session,
	# which is the defect the whole issue is about.
	lease_lost
	spec_head holder-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" != *"admitted as the successor"* ]]
	[ "$(call_order)" = "" ]
	[ "$(ready_calls)" = "" ]
}

@test "the successor reserves only once, however many laps it waits" {
	# Re-reserving each lap would rewrite the ref to say what it already says.
	lease_lost
	spec_head holder-branch
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=3 run "$LAND"
	[ "$(lock_calls reserve)" -eq 1 ]
}

@test "MAIN MOVING DURING THE WAIT: the winner laps rather than confirming a doomed head" {
	# `acquire` waits up to a full TTL, so the winner is at its most stale in the
	# instant it wins. Readying here buys a matrix the fast-forward will refuse —
	# which is the oldest waste in this loop, measured on PR #325 as 8 laps, 8
	# greens and zero commits landed.
	echo 0ther0ther0ther0 >"$BATS_TEST_TMPDIR/main_moves_in_wait"
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=2 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"main moved to"* ]]
	[[ "$output" == *"lapping rather than confirming a head it will refuse"* ]]
	# Nothing spent, and the lease handed straight back rather than held across
	# a rebase the next lap will do anyway.
	[ "$(call_order)" = "" ]
	[ "$(lock_calls release)" -ge 1 ]
}

@test "a lap whose main did not move confirms and proceeds — the negative of the case above" {
	# Without this, a re-confirmation that ALWAYS lapped would pass the case
	# above and land nothing, ever.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" != *"lapping rather than confirming"* ]]
	[[ "$(call_order)" == *push* ]]
}

@test "the successor's run is bought ONCE, not re-pushed on every lap it waits" {
	# A successor waits many laps by design. Re-entering the ready/push pair each
	# time would push an unchanged head — which emits no `synchronize`, buys
	# nothing, and drops into the `--undo` re-fire path that exists for a
	# different case entirely.
	lease_lost
	spec_head holder-branch
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=3 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$(call_order)" == "ready push"* ]]
	[ "$(grep -c '^push$' "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
	[[ "$output" == *"its run is already in flight"* ]]
}
