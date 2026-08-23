#!/usr/bin/env bats
# subject: mise-tasks/land.sh
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
	REAL_LAND="$BATS_TEST_DIRNAME/../mise-tasks/land.sh"
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
	# CLOUD-413: the backoff honours a delay the SERVER states, so a case that
	# scripts a real one would pay it in wall clock. The floor and the cap are the
	# two knobs that bound it; the cases that assert the delay set the header and
	# read what was chosen, rather than sleeping to prove a number.
	export LAND_RATE_FLOOR=0
	export LAND_RATE_PAUSE_MAX=0
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
  # CLOUD-483: re-running the failed jobs of a run that never reached a verdict.
  # Recorded by run id, so a case asserts WHICH run was re-run rather than that
  # something was — and \`rc.rerun\` scripts the refusal arm.
  "run rerun")
    # \`\$all\`, not a positional: the parsing loop above has already shifted every
    # argument away by the time this arm runs.
    echo "\$all" >>"$BATS_TEST_TMPDIR/reruns"
    [ ! -f "$BATS_TEST_TMPDIR/rc.rerun" ] || exit 1
    echo rerun ;;
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
  # endpoint does. Without that a case cannot tell \$(--state open) from its
  # absence, and the assertion that \$(land) binds the open PR proves nothing —
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
        # CLOUD-413: \`land\` asks with \`-i\`, so this answers the way the real
        # endpoint does — headers, a blank line, then the body. The rate-limit
        # headers are the whole point of the refusal path: the delay is STATED
        # there, and asking a second endpoint for it would be one more request
        # against the limit that just refused this one.
        if [ -f "$BATS_TEST_TMPDIR/rc.comment" ]; then
          echo "HTTP/2.0 403"
          cat "$BATS_TEST_TMPDIR/limit-headers" 2>/dev/null
          echo
          echo '{"message":"API rate limit exceeded","status":"403"}'
          echo "GraphQL: was submitted too quickly (addComment)" >&2; exit 1
        fi
        echo "\$all" >>"$BATS_TEST_TMPDIR/comments"
        echo "HTTP/2.0 201"
        echo "content-type: application/json"
        echo
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
	# CLOUD-345: whether the branch still EXISTS on the remote, which is a
	# different question from what SHA it is at. Present by default — the ordinary
	# world — so a rejected push means a concurrent writer unless a case says
	# otherwise. Empty output is how `git ls-remote --heads` reports absence.
	printf 'deadbeef\trefs/heads/feat\n' >"$BATS_TEST_TMPDIR/lsremote"
	echo cafe1234cafe1234 >"$BATS_TEST_TMPDIR/headsha"
	echo ma1nma1nma1nma1n >"$BATS_TEST_TMPDIR/mainsha"
	echo 5peccccc5peccccc >"$BATS_TEST_TMPDIR/specsha"
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_rebase"
	echo 0 >"$BATS_TEST_TMPDIR/rc.reset"
	# 0 by default: the bet is LIVE — the branch the lease names still carries the
	# base we bet on, which is what "the holder is still landing" looks like. The
	# defect CLOUD-495 fixes is reading every pending bet as this one.
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_live"
	echo 0 >"$BATS_TEST_TMPDIR/rc.fetch_live"
	# 1 by default: the holder's head is NOT already in our history, and the base
	# we bet on has NOT landed. Both are the ordinary readings — a lease is held
	# by someone whose work is still in flight.
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_ancestor"
	# CLOUD-862's two, defaulted so every case that is not about recovery behaves
	# exactly as before: 1 = the adopted base has not landed, and 1 = this tree
	# is not built on it. With no `specbet` file written, `recover_speculation`
	# returns on its first read and neither is consulted at all.
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_landed"
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_ontree"
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
  # The liveness fetch has its own rc (CLOUD-495): rc.fetch is the fetch of
  # \`main\`, whose failure is a die, and a case about an unreadable LEASE must not
  # be forced to stop the whole lap to say so.
  "fetch"*refs/batten-spec/live) exit "\$(cat "$BATS_TEST_TMPDIR/rc.fetch_live")" ;;
  "fetch"*)                      exit "\$(cat "$BATS_TEST_TMPDIR/rc.fetch")" ;;
  # TWO DIFFERENT ANCESTRY QUESTIONS, and one file could not answer both. The
  # lap asks "am I a descendant of main"; CLOUD-369's speculation asks "is the
  # holder's head already in my history" and "did the base I bet on land". A
  # single rc made the second answer yes by accident, and the speculation
  # silently returned early — which the suite then reported as the mechanism
  # never having run.
  "merge-base --is-ancestor origin/main HEAD") exit "\$(cat "$BATS_TEST_TMPDIR/rc.linear")" ;;
  # A THIRD ancestry question (CLOUD-495): "is the base I bet on still carried by
  # the branch the lease names NOW". The comment above is the reason this needs
  # its own file rather than another caller of rc.spec_ancestor — an rc that
  # answered two questions is what made the speculation silently no-op once.
  "merge-base --is-ancestor"*refs/batten-spec/live) exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_live")" ;;
  # A FOURTH and FIFTH (CLOUD-862), and they exist for the reason the comment
  # above gives twice already: recovering a bet left by a dead run asks "did the
  # adopted base land" and "is this tree actually built on it", and one rc
  # answering both is how a recovery would silently decide it had nothing to do.
  # Ordered before the catch-all and after the exact linearity arm, since the
  # adopted sha is a wildcard on the left of each.
  "merge-base --is-ancestor"*origin/main) exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_landed")" ;;
  "merge-base --is-ancestor"*HEAD) exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_ontree")" ;;
  "merge-base"*)                 exit "\$(cat "$BATS_TEST_TMPDIR/rc.spec_ancestor")" ;;
  "rev-parse --verify -q refs/batten-spec/base") cat "$BATS_TEST_TMPDIR/specbet" 2>/dev/null || exit 1 ;;
  "update-ref -d refs/batten-spec/base") rm -f "$BATS_TEST_TMPDIR/specbet"; exit 0 ;;
  "ls-remote --heads origin "*)  cat "$BATS_TEST_TMPDIR/lsremote" ;;
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
# CLOUD-774: filed-here-check is fed the PR body so it can exempt a row this PR
# closes. Recorded here so a case can assert the body actually arrives -- a gate
# wired to read stdin that nobody pipes to is inert, and it shipped inert once.
# NO BACKTICKS IN THIS HEREDOC: it is unquoted, so a backticked word is command
# substitution and the comment would try to RUN the task it names.
# CLOUD-995: a real gate can exit BEFORE it reads stdin. filed-here-check does
# exactly that under its bypass and on a detached HEAD, and closing-key-check on
# every could-not-read path. Modelled here, ahead of every read, so a case can
# prove the EPIPE it leaves the producer with is not read as a refusal. Only a
# case that asks for it is affected, so what CLOUD-774 pins below is untouched.
if [ -f "$BATS_TEST_TMPDIR/nodrain.\$2" ]; then exit 0; fi
if [ "\$2" = filed-here-check ]; then cat >"$BATS_TEST_TMPDIR/filedhere.stdin"; fi
rc="$BATS_TEST_TMPDIR/rc.mise.\$2"
if [ -f "\$rc" ]; then
  code=\$(cat "\$rc")
  # A failure can be scripted for ONE call rather than for the whole run, which
  # is what a lap-and-recover case needs: the second lap must see the task pass.
  [ ! -f "\$rc.once" ] || rm -f "\$rc" "\$rc.once"
  # CLOUD-407's lever: the failing gate's OWN words, before the generic line. A
  # real refusal names \`path:line\`, and the whole defect was that those lines
  # existed and never reached the operator — so a case has to be able to write
  # them and then assert they came back out.
  [ ! -f "\$rc.says" ] || cat "\$rc.says" >&2
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
  # CLOUD-483: the classification of a red run, owned by \`nonverdict-scan\` and
  # only consulted here. Records come from a file so a case scripts the answer;
  # the DEFAULT IS EMPTY, which is "could not look" and keeps today's red
  # message — so every pre-existing red-path row is untouched by this arm.
  nonverdict-scan)
    cat "$BATS_TEST_TMPDIR/nonverdict" 2>/dev/null || true
    exit 0 ;;
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
  # CLOUD-192's stop, and the same lever. Passes by default so the cases that
  # care about anything else do not each have to write a closing body.
  closing-key-check) exit 0 ;;
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
      # THE HOLDER GOES AWAY WHILE MAIN STAYS PUT (CLOUD-495). The lease is a
      # ref, so abandonment is observable exactly as a change to what \`peek
      # branch\` answers — the lease freed (empty), or taken by somebody else.
      # Same shape as the main-moves lever, and fired from the same lap on, so
      # the bet is placed before the world moves under it.
      if [ -f "$BATS_TEST_TMPDIR/lease_abandons_after" ] &&
        [ "\$n" -ge "\$(cat "$BATS_TEST_TMPDIR/lease_abandons_after")" ]; then
        cat "$BATS_TEST_TMPDIR/lease_abandons_to" >"$BATS_TEST_TMPDIR/lease.branch"
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

# CLOUD-470: the lease says STOP for this branch. `land-lock authorises` is the
# ONE authority on "was this run declined" — the same verb the runner's own
# precondition consults — so the declination is scripted through its exit code
# (3 = stop) rather than through a second reading of the run list. Swapping the
# raw `conclusion == "cancelled"` read for this is the whole change; the rows
# below assert the same behaviour they always did.
lease_declines() { echo 3 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.authorises"; }
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
# CLOUD-995. A task that succeeds WITHOUT reading the stdin it was handed, which
# is what a gate's own early exit looks like from the caller's side.
task_exits_undrained() { : >"$BATS_TEST_TMPDIR/nodrain.$1"; }
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

# A FULL page — 100 strangers' refusals, none of them ours. Fullness is the
# signal, not the content: a short page means the `created>=SINCE` window ended,
# and a full one means it did not, so this is the only fixture that makes a
# second page be fetched at all (CLOUD-456's depth half).
full_page_of_strangers() {
	jq -nc '{workflow_runs: [range(100) | {
	  created_at: "2099-01-01T00:00:00Z", status: "completed", conclusion: "failure",
	  display_title: ("fast-forward #999 @" + (. | tostring))}]}' >"$BATS_TEST_TMPDIR/$1"
}
comment_fails() { : >"$BATS_TEST_TMPDIR/rc.comment"; }

# CLOUD-413: what the refused response STATES about when to come back. Written as
# real header lines so the parser is exercised on the shape it will actually meet,
# case included — GitHub sends `Retry-After`, not `retry-after`.
states_retry_after() { printf 'Retry-After: %s\n' "$1" >"$BATS_TEST_TMPDIR/limit-headers"; }
states_ratelimit_reset() {
	printf 'X-RateLimit-Remaining: 0\nX-RateLimit-Reset: %s\n' \
		"$(($(date -u +%s) + $1))" >"$BATS_TEST_TMPDIR/limit-headers"
}
states_no_limit_headers() { : >"$BATS_TEST_TMPDIR/limit-headers"; }
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

@test "this lap's own run is read even when it fell off the first page (CLOUD-456)" {
	# THE DEPTH HALF, and it is a separate defect from the key. A keyed filter
	# over a window that has already rolled past this lap's run returns empty,
	# which the poll reads as "not answered yet" — byte-identical to a silent
	# bot, and that is the reading CLOUD-399 recorded as "the bot is slow" while
	# the bot was answering inside 23 seconds. At the measured 13 runs/minute one
	# page of 100 is ~7.7 minutes and a lap routinely outlives it. Page one here
	# is 100 strangers; ours is on page two.
	pr_state OPEN MERGED
	full_page_of_strangers runs.1
	workflow_runs runs.2 failure
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the fast-forward bot refused (failure)"* ]]
	[ "$(comments)" -eq 2 ]
}

@test "paging stops at the short page instead of walking history (CLOUD-456)" {
	# The negative control for the row above, and the termination argument
	# itself: the walk ends because `created>=SINCE` bounds the SET, so a short
	# page IS the end of the window. A reader that kept paging would find an
	# older lap's own run and re-read it as this lap's verdict — the livelock
	# the SINCE stamp exists to prevent. Nothing keyed to us exists on either
	# page, so this lap gets no verdict and does not lap.
	pr_state OPEN OPEN MERGED
	full_page_of_strangers runs.1
	sibling_refuses runs.2
	workflow_runs runs.last
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" != *"the fast-forward bot refused"* ]]
	[ "$(comments)" -eq 1 ]
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

@test "CLOUD-413: a refused comment waits the retry-after the response STATES" {
	# Measured on PR #323: 24 laps across three invocations, never merging, and not
	# one lap failed for any of the three reasons `land` stops on. Several refusals
	# were a 403 rate limit that `land` could not tell from "main moved" — so its
	# response to being rate-limited was to generate more of exactly the request
	# that was rate-limited, each retry costing a verify, a CI run and a comment.
	#
	# Lapping with NO delay is not backoff; it is the same request again.
	comment_fails
	states_retry_after 7
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"retry-after"* ]]
	[[ "$output" == *"7s"* ]]
	# And it never enters the answer poll: polling for the answer to a question
	# nobody received is the CLOUD-235 hang with a different cause.
	[ "$(comments)" -eq 0 ]
	# The lap was refunded — a refused comment spent no CI, so it must not be
	# charged to the budget that exists to catch a moving `main`.
	[[ "$output" != *"moving faster than a lap takes"* ]]
}

@test "CLOUD-413: with no retry-after it waits until x-ratelimit-reset" {
	comment_fails
	states_ratelimit_reset 30
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	# The RESET TIME, which the code had all along and used to throw away in
	# favour of telling the human to go run `gh api rate_limit` for it.
	[[ "$output" == *"rate limit resets at"* ]]
	[[ "$output" != *"gh api rate_limit"* ]]
}

@test "CLOUD-413: a response stating no limit headers still waits a floor" {
	# Some delay beats none. The floor is the only guessed number here, and it is
	# reached only when the server states nothing.
	comment_fails
	states_no_limit_headers
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"stated no limit headers"* ]]
}

@test "CLOUD-413: exhausting the budget names the LIMIT, not a moving main" {
	# The second finding from the same run. Over those 24 laps the exhaustion
	# message — "main is moving faster than a lap takes" — was wrong twice over:
	# 7 of 8 laps in one invocation reached green CI, and several refusals were the
	# rate limit rather than `main` at all. A diagnosis that names the wrong cause
	# sends the reader to look in the wrong place.
	comment_fails
	states_retry_after 3
	pr_state OPEN
	LAND_ANSWER_MAX_UNKNOWNS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no readable answer"* ]]
	[[ "$output" == *"retry-after"* ]]
	[[ "$output" != *"moving faster than a lap takes"* ]]
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
	# It used to end by telling the reader to go run `gh api rate_limit` — asking
	# a human to fetch a number the code had already been handed. CLOUD-413 makes
	# the message carry what the response stated; on this path the runs query was
	# refused rather than the comment, so no limit headers were read and the note
	# says so rather than inventing a reset time.
	[[ "$output" != *"gh api rate_limit"* ]]
	[[ "$output" == *"mise run land"* ]]
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
	# AND THE MINTED KEY MUST CARRY BOTH IDS. A `run-name:` line that survives
	# the grep above while its value is truncated to the bare workflow name is
	# exactly how the filter stayed dead for a day: the unquoted `#` opened a
	# YAML comment and ate both interpolations, and every reading — a passing
	# run and a broken filter — was the same bytes (CLOUD-507).
	run grep -cE '^run-name:.*github\.event\.issue\.number.*github\.event\.comment\.id' \
		"$BATS_TEST_DIRNAME/../.github/workflows/fast-forward.yml"
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

@test "CLOUD-510: a racer land killed on purpose delivers no verdict" {
	# DIAGNOSIS FIRST, because the issue offered two mechanisms and they land the
	# fix in different places. Measured 2026-08-13 against post-CLOUD-383 `land`,
	# with a real nested `mise run` of a real file task, inside and outside a
	# mise-managed process group, under both the current FIFO rendezvous and the
	# pre-CLOUD-383 bare `wait -n`: the killed child's own
	# `ERROR … exited with non-zero status: no exit status` / `task failed` lines
	# DO appear — they are the child mise's diagnostics — but they arrive after
	# the parent has already read the rc files, and the parent exits 0 and laps.
	# So "a killed nested task aborts the parent" is REFUTED; those lines are
	# noise correlated with the kill rather than its consequence.
	#
	# What the measurement did expose is a real ordering hazard, and it is the
	# issue's own title read literally. The two racers answer at the same instant
	# by construction, so nothing stops the loser finishing on its OWN in the
	# window between the winner reaching the rendezvous and the group kill
	# landing: `ci-wait` returning a red verdict in the same breath as
	# `main-watch` reporting that main moved. Emptiness is a PROXY for "this
	# racer lost"; the rendezvous token is the fact.
	#
	# The environment cannot deterministically create that window — it is bounded
	# by a kill, and a timing-based setup would pass vacuously on a loaded box,
	# which is the CLOUD-249 defect this repo has already paid for once. So the
	# DECISION is extracted and driven directly, which is what
	# `.claude/rules/rust.md` prescribes for exactly this case.
	local block
	block=$(awk '/^\tcase "\$ciwinner" in/{p=1} p{print} p&&/^\tesac$/{exit}' "$REAL_LAND")
	[ -n "$block" ]

	# main-watch won, and ci-wait ALSO finished on its own with a red verdict
	# before the kill landed. That verdict is about a SHA that is no longer
	# landable, and the run behind it is superseded by the next lap's push
	# through `concurrency: cancel-in-progress`. Stopping the landing on it
	# reports a red nobody needs to fix.
	run bash -c "ciwinner=m; ci_rc=1; main_rc=0; $block; echo \"ci_rc='\$ci_rc' main_rc='\$main_rc'\""
	[ "$status" -eq 0 ]
	[ "$output" = "ci_rc='' main_rc='0'" ]

	# The mirror, and the reason this is not simply "ignore ci_rc": ci-wait won,
	# so ITS code is the verdict and main-watch's is the void one.
	run bash -c "ciwinner=c; ci_rc=1; main_rc=0; $block; echo \"ci_rc='\$ci_rc' main_rc='\$main_rc'\""
	[ "$output" = "ci_rc='1' main_rc=''" ]

	# An unreadable rendezvous names no winner, and then nothing is voided — the
	# fallback is exactly the reading this file had before CLOUD-510, so a FIFO
	# that could not be read never invents a lap.
	run bash -c "ciwinner=; ci_rc=1; main_rc=0; $block; echo \"ci_rc='\$ci_rc' main_rc='\$main_rc'\""
	[ "$output" = "ci_rc='1' main_rc='0'" ]

	# The VERIFY race carries the identical hazard and the identical block, so it
	# is asserted here rather than left to be discovered when only one of the two
	# gets fixed. A verify that refused the tree in the same breath as main
	# moving is a refusal of a tree the next lap rebases away.
	local vblock
	vblock=$(awk '/^\t\tcase "\$vwinner" in/{p=1} p{print} p&&/^\t\tesac$/{exit}' "$REAL_LAND")
	[ -n "$vblock" ]
	run bash -c "vwinner=m; verify_rc=1; vmain_rc=0; $vblock; echo \"verify_rc='\$verify_rc' vmain_rc='\$vmain_rc'\""
	[ "$output" = "verify_rc='' vmain_rc='0'" ]
	run bash -c "vwinner=v; verify_rc=1; vmain_rc=0; $vblock; echo \"verify_rc='\$verify_rc' vmain_rc='\$vmain_rc'\""
	[ "$output" = "verify_rc='1' vmain_rc=''" ]
}

@test "CLOUD-510: a genuine ci-wait failure still stops the lap" {
	# The negative self-test. Voiding the loser must not become voiding every
	# non-zero: when `ci-wait` wins its own race and answers red, that is a
	# verdict about this branch and the landing stops on it, exactly as before.
	task_fails ci-wait
	head_is_graded
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
}

@test "CLOUD-407: a refused tree stops on lap 1 and carries the gate's own pointers" {
	# Measured on PR #322. `batten check` refused three files by name, `verify`
	# passed that refusal out as exit 2 through its `depends`, and `land` read the
	# 2 as "main moved" — eight laps, ~13 minutes, and an operator told to "look
	# before lapping again" at a branch whose defect was three `path:line`
	# pointers printed twenty lines above every one of those messages.
	#
	# Two halves, and this row is the second. tests/verify.bats holds the first:
	# `verify` can no longer mint a 2 for content at all. What is left for `land`
	# is to stop on lap 1 AND to say what was actually refused.
	task_fails verify
	printf '%s\n' \
		'[hooks] batten-check stderr:' \
		'[hooks] crates/batten/tests/primitives.rs:1171 no-consumer-repo-name' \
		'[hooks] crates/batten/tests/primitives.rs:1174 no-consumer-repo-name' \
		>"$BATS_TEST_TMPDIR/rc.mise.verify.says"
	run "$LAND"
	[ "$status" -eq 1 ]
	# Lap 1, not the backstop. Same assertion as the plain stop above, restated
	# here because the CODE is what used to decide it and no longer does.
	[ "$(verify_calls)" -eq 1 ]
	[ "$(comments)" -eq 0 ]
	# The pointers survived the race, the tee, and the message assembly.
	[[ "$output" == *"primitives.rs:1171 no-consumer-repo-name"* ]]
	[[ "$output" == *"primitives.rs:1174 no-consumer-repo-name"* ]]
	# And it is NOT reported as the benign race, which is the whole defect.
	[[ "$output" != *"that is a rebase"* ]]
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

@test "the lap cap's refusal states what its own accounting supports" {
	# CLOUD-904, and the first of a PAIR — the second case below reads this one's
	# remedy against the fleet-saturated one, which is the assertion neither of them
	# used to make.
	#
	# `charge_wait` REFUNDS the lap on every path that bought no CI, so reaching the
	# cap means exactly one thing: this branch spent `max_laps` matrices and none of
	# them landed. It does NOT mean `main` outran a lap — that inference is the one
	# the refunds removed, and the same diagnosis CLOUD-413 measured wrong twice over
	# across 24 laps. The message asserted it anyway for as long as the refunds have
	# existed.
	#
	# CLOUD-871's worked instance lives here too: the remedy must name a runnable
	# object rather than ask for judgement. An agent read "Look before lapping again"
	# as STOP and stopped for 55 minutes on a one-commit branch, which is the worst
	# move available — this task's own header says lapping IS the catch-up mechanism,
	# so a stopped branch ages while the target moves.
	#
	# DELIBERATELY SINGULAR — do not copy this for the other refusals. There are 420
	# terminal refusals under `mise-tasks/`, and a case apiece would be 420 bespoke
	# assertions in the language the retirement campaign exists to delete. A text
	# predicate over the class was measured and is unshippable: against a generous
	# detector only 103 of 420 name a runnable object, so it fires on 75%, and most
	# of that is good messages. Rego cannot do better — regorus is built here with no
	# `regex` builtins (CLOUD-885). The general property is acquired STRUCTURALLY
	# instead: a rule kind requires `no_fix_reason` and ingest refuses a finding with
	# no remedy, which a gate gets the moment it becomes a policy row (CLOUD-843).
	echo 2 >"$BATS_TEST_TMPDIR/rc.mise.verify"
	LAND_MAX_LAPS=2 run "$LAND"
	[ "$status" -eq 5 ]
	# What the accounting supports: the spend COUNTED at the ready, and that it
	# did not land. Zero here is the discriminating value — these laps fail
	# `verify`, so the ready is never reached and nothing is bought. Asserting a
	# spend equal to the lap count is exactly the overstatement this replaced:
	# measured on PR #651, two such laps reported "spent 2 CI matrices" against
	# zero check-runs on the head.
	[[ "$output" == *"bought 0 CI matrices"* ]]
	[[ "$output" == *"landed nothing"* ]]
	[[ "$output" != *"spent 2 CI matrices"* ]]
	# The refuted inference must not be asserted at the emission site. The literal
	# is allowed in the file's explanatory comments, which earn it by describing the
	# bug — this reads the REFUSAL, not the file.
	[[ "$output" != *"is moving faster than a lap takes"* ]]
	# A runnable object, not "look".
	[[ "$output" == *"gh pr view"* ]]
	# And the wording that caused the 55-minute stop must not come back.
	[[ "$output" != *"Look before lapping again"* ]]
}

@test "the two exhaustions give imperatives consistent with their costs" {
	# CLOUD-904's discriminating assertion, and the reason it is a PAIR: each case
	# reads BOTH messages. CLOUD-399 made the two exits distinguishable by code and
	# their remedies were never reconciled — the path that cost NOTHING told the
	# caller to stop, and the path that cost `max_laps` matrices was ambiguous.
	# "Free implies stop, expensive implies go" is not a defensible pairing, and no
	# single-message assertion can see it.
	#
	# The unspent path may say wait. The spent path must name a continuing action AND
	# the spend the caller is re-committing — an unconditional "run this again"
	# re-arms the only brake on that spend.
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	saturated="$output"

	setup

	echo 2 >"$BATS_TEST_TMPDIR/rc.mise.verify"
	LAND_MAX_LAPS=2 run "$LAND"
	[ "$status" -eq 5 ]
	runaway="$output"

	# The unspent path names its zero cost and names waiting.
	[[ "$saturated" == *"spent no CI matrix"* ]]
	[[ "$saturated" == *"wait, or land later"* ]]

	# The spent path names the cost it already paid, counted rather than inferred.
	[[ "$runaway" == *"bought 0 CI matrices"* ]]
	# ...names a continuing action...
	[[ "$runaway" == *"run this again"* ]]
	# ...and names the spend that action re-commits, which is what stops the
	# continuing imperative from being unconditional.
	[[ "$runaway" == *"commits up to another 2"* ]]

	# The remedies must not be interchangeable: the expensive path must not be
	# telling the caller to wait, which is the free path's answer.
	[[ "$runaway" != *"wait, or land later"* ]]
}

@test "a verify that keeps losing the race exhausts laps rather than spinning" {
	# The lap is bounded by the backstop that already exists. A `main` that
	# never stops moving must reach LAND_MAX_LAPS and say so, not loop forever.
	echo 2 >"$BATS_TEST_TMPDIR/rc.mise.verify"
	LAND_MAX_LAPS=3 run "$LAND"
	[ "$status" -eq 5 ]
	# CLOUD-904 rewrote this refusal: "still not linear" asserted that `main`
	# outran a lap, which the refunds in `charge_wait` already make impossible.
	# What this case is about is the BACKSTOP firing after N laps, so it matches
	# on the count rather than on the diagnosis that used to accompany it.
	[[ "$output" == *"after 3 laps"* ]]
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
	# CLOUD-904 removed the refuted diagnosis this used to match on. The subject of
	# THIS case is the exit CODES, so it needs any string that identifies the runaway
	# refusal; the content of that refusal is the pair of cases above.
	[[ "$output" == *"landed nothing"* ]]

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

@test "a row this branch filed without grooming it stops before review is asked for" {
	# CLOUD-514's stop, and the sibling of the one above: `deferral-check` prices
	# a decision left with no home, this prices a home opened instead of a fix.
	# The gate reads `board-write-record`'s own file for the rows; the PR body
	# reaches it on stdin (CLOUD-774) only so it can exempt a row this PR closes.
	# The lever here is still the task's exit status, which is what `land` acts on.
	#
	# Asserted before the comment count for the reason every stop above is:
	# stopping after asking for the merge would have already spent what the stop
	# exists to withhold.
	task_fails filed-here-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"filed a row that was never groomed to Ready"* ]]
	[ "$(comments)" -eq 0 ]
}

# CLOUD-774. THE WIRE, not just the gate. `filed-here-check` grew a closing-key
# exemption so a row this PR closes is not read as a punt — and that exemption is
# inert unless `land` actually pipes the body to it. It shipped inert once: the
# first landing after the gate changed refused two rows the PR closes, because the
# call site still passed nothing on stdin.
@test "THE PR BODY REACHES filed-here-check, or its exemption is inert" {
	# The stub captures stdin BEFORE it consults the scripted exit code, so making
	# the gate fail is a lever that stops the lap immediately and still proves what
	# the call site handed it. Letting `land` run on would poll CI and never end.
	pr_body "Closes CLOUD-900"
	task_fails filed-here-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[ -f "$BATS_TEST_TMPDIR/filedhere.stdin" ]
	[[ "$(cat "$BATS_TEST_TMPDIR/filedhere.stdin")" == *"Closes CLOUD-900"* ]]
}

# CLOUD-995. THE GATE'S OWN EXIT, not the pipeline's. `land` runs under pipefail,
# so a gate that exits before reading leaves the producer with EPIPE and the
# pipeline reports failure -- and `land` then reports the gate as having REFUSED.
# Two gates do exit early: filed-here-check returns 0 under its bypass and on a
# detached HEAD, closing-key-check exits 2 on every could-not-read path. So the
# bypass reddened the very lap it exists to wave through.
#
# THE BODY HAS TO BE BIGGER THAN THE PIPE BUFFER or the case proves nothing: a
# short one fits in the kernel buffer, the producer completes before the reader
# is gone, and the old piped form passes too. At 100k the write blocks and the
# EPIPE is certain, which is what makes this able to fail against the old shape.
#
# closing-key-check is failed on purpose so the lap stops somewhere nameable;
# without it `land` would run on to the CI poll and never end.
@test "CLOUD-995: a gate that exits before reading stdin is not a refusal" {
	pr_body "$(printf 'x%.0s' $(seq 1 100000)) Closes CLOUD-900"
	task_exits_undrained filed-here-check
	task_fails closing-key-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" != *"filed a row that was never groomed to Ready"* ]]
	[[ "$output" == *"names its issue but never closes it"* ]]
}

@test "a body that names its issue but never closes it stops before review is asked for" {
	# CLOUD-192's stop, and it sits beside the deferral one for the same reason:
	# readying is the commitment to review, and the board move is what tells
	# anyone review is open. A PR that only MENTIONS its issue links, attaches
	# and moves nothing — measured as #398 (`Refs:`, never moved) against #400
	# (`Closes`, moved in two seconds).
	#
	# Asserted before the comment count, like the two stops above: stopping after
	# asking for the merge would have already spent what the stop withholds.
	pr_body "Some work here.

Refs: CLOUD-192"
	task_fails closing-key-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"names its issue but never closes it"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "a prose-only branch stops before review is asked for" {
	# CLOUD-827's stop, and the only one in this set that prices what the change is
	# WORTH rather than whether it is correct. Measured: a branch whose whole diff
	# was two rewritten sentences of `//!` doc comment reached the ready and a full
	# required matrix, and what stopped it was a human rather than a gate.
	#
	# Asserted before the comment count for the reason every stop here is: stopping
	# after asking for the merge would already have spent the thing the stop exists
	# to withhold — and here that thing IS the spend.
	task_fails prose-only-check
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"prose-only branch"* ]]
	[ "$(comments)" -eq 0 ]
	# It must not have readied either: the ready is the event that buys the run.
	[ "$(grep -c '^ready$' "$BATS_TEST_TMPDIR/calls")" -eq 0 ]
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
	lease_declines
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CANCELLED"* ]]
	[[ "$output" == *"git rebase origin/main"* ]]
	[[ "$output" != *"verify and CI disagree"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "CLOUD-470: the declination is asked of land-lock, not re-derived" {
	# THE MECHANISM, not the behaviour — the behaviour is the pair above. The Ready
	# block is explicit that this "calls `land-lock authorises` or it is wrong",
	# and the first cut answered the same question from a raw
	# `conclusion == "cancelled"` read of the run list. Two authorities for one
	# fact is the CLOUD-351 shape, where only the newer one decides.
	#
	# Structural, because the behavioural pair cannot tell the two implementations
	# apart: both print the same message. This is what fails if the verb is swapped
	# back out for a second predicate.
	lease_declines
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[ "$(lock_calls authorises)" -ge 1 ]
	run grep -c 'authorises' "$REAL_LAND"
	[ "$output" -ge 1 ]
	# And the raw fingerprint is gone: no second reading of the run list decides
	# "declined". `cancel_own_run` still reads that endpoint for a different
	# question — which runs are still in flight — so the assertion is on the
	# conclusion literal, not on the endpoint.
	#
	# CODE ONLY. The comment above `declined_by_lease` names the predicate it
	# replaced, which is the design record and must survive; a sensor that read it
	# as the defect would pressure the next author to delete the explanation.
	[ "$(grep -vE '^[[:space:]]*#' "$REAL_LAND" | grep -c 'conclusion == "cancelled"')" -eq 0 ]
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

@test "CLOUD-376: an unset ANSWERED set stops rather than readying, for the same reason" {
	# The second input `graded_runs` cannot compute, guarded in the same place and
	# not inside the function: both call sites wrap it in `$( )`, so a `:?` abort
	# there exits the SUBSHELL only and the lap continues with an empty reading —
	# which both call sites read as "no graded run", the branch that fires the
	# ready that spends a matrix. That is CLOUD-467's defect in a new variable, and
	# it would have shipped with the refactor that introduced it.
	CI_ANSWERED_CONCLUSIONS= run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI_ANSWERED_CONCLUSIONS is unset"* ]]
	[ "$(ready_calls)" = "" ]
	[ "$(comments)" -eq 0 ]
}

@test "CLOUD-376: no conclusion name is written in mise-tasks outside the manifest" {
	# The sensor on the property, in the shape `ci-local-parity` already uses for
	# CI_REQUIRED_CHECKS. Without it this is a refactor that silently un-refactors:
	# the next edit re-inlines a literal, the two readers drift again, and nothing
	# notices until they compose into a wedge — which is precisely how CLOUD-363
	# happened, and it was found by a human reading both files.
	#
	# `success` and `neutral` are exempt: they name GREEN, which is a narrower
	# question than "is this an answer" and is not what the manifest declares.
	#
	# SCOPED TO THE TWO READERS THAT SHARE THE MANIFEST, and the exemption is
	# stated rather than silent. `sonar-gate` judges ONE external check-run by
	# name, deliberately outside `$CI_REQUIRED_CHECKS` (CLOUD-441) — a different
	# roster answering a different question, so a literal there is not a second
	# copy of this one and forcing it to share would couple two unrelated gates.
	# CODE ONLY, for the reason the CLOUD-470 sensor gives: a comment naming the
	# literal it removed is the design record, and a sensor that read it as the
	# defect would pressure the next author to delete the explanation.
	local leaked=""
	for c in timed_out action_required cancelled; do
		for f in mise-tasks/land.sh mise-tasks/checks-green.sh; do
			[ "$(grep -vE '^[[:space:]]*#' "$BATS_TEST_DIRNAME/../$f" | grep -c "\"$c\"")" -eq 0 ] ||
				leaked="$leaked $f:$c"
		done
	done
	[ -z "$leaked" ] || {
		echo "conclusion literals outside mise.toml [env]:$leaked"
		echo "Declare them once in CI_ANSWERED_CONCLUSIONS; two hand-maintained lists is CLOUD-363."
		return 1
	}
}

@test "a rejected push stops rather than clobbering someone else's branch" {
	# `--force-with-lease` is what makes this a stop and not data loss: the
	# lease is stale the moment another writer moves the branch.
	fails push
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"push rejected"* ]]
	[ "$(comments)" -eq 0 ]
	# CLOUD-345's anti-vacuity half: a GENUINE concurrent move keeps today's
	# caution and must never be told to prune. A change that always named the
	# stale ref would pass the row below and send an operator to force over a
	# writer who is really there.
	[[ "$output" == *"Someone else moved it"* ]]
	[[ "$output" != *"--prune"* ]]
}

@test "CLOUD-345: a branch ABSENT from the remote is a stale ref, not a rival" {
	# The deadlock. GitHub deletes the head branch on merge, a plain fetch never
	# prunes, and the surviving tracking ref names a SHA the remote does not have
	# — so `--force-with-lease` is rejected as `stale info` forever. No number of
	# laps clears it, because every lap re-fetched without pruning.
	#
	# The old message named the one cause that was not true, and named it toward
	# the dangerous action: `git log HEAD..origin/<branch>` is EMPTY here, so
	# every check an operator would run says forcing is safe, for the wrong
	# reason.
	fails push
	: >"$BATS_TEST_TMPDIR/lsremote"
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ABSENT from the remote"* ]]
	[[ "$output" == *"--prune"* ]]
	[[ "$output" == *"Do NOT force"* ]]
	[[ "$output" != *"Someone else moved it"* ]]
	[ "$(comments)" -eq 0 ]
}

@test "CLOUD-345: every fetch prunes, so a deleted upstream leaves no expectation" {
	# The cheap half, and the one that makes the loop self-clearing rather than
	# merely better-diagnosed. `fetch_main` is the single definition both lap
	# reads share, so this covers both.
	pr_state MERGED
	run "$LAND"
	grep -qE '^fetch -q --prune origin main$' "$BATS_TEST_TMPDIR/gitlog"
	[ "$(grep -cE '^fetch -q origin main$' "$BATS_TEST_TMPDIR/gitlog")" -eq 0 ]
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
	# 24 since CLOUD-483: absorbing a provisioning transient adds two — a re-run
	# the API refused, and the retry budget exhausted. Both exercised below; the
	# budget one is a COUNT, so the no-wall-clock row above still holds.
	# 26 since CLOUD-383: a race rendezvous that cannot be created, once per race.
	# 27 since CLOUD-192: a PR body that names its issue but never closes it, so
	# the merge would leave the board a column behind. Exercised below.
	# TWO stops rather than one on purpose — the helper RETURNS the failure and
	# each caller dies at top level, because a `die` inside the `$( )` every
	# caller wraps it in would exit only the subshell (CLOUD-467, measured again
	# here). Both are exercised below.
	# 28 since CLOUD-518: a PR whose webhook subscription this session has not
	# dropped. It is the FIRST stop in the run, before the singleton and the lease,
	# so a refusal costs no CI at all — and this counter caught it the moment it
	# was added, which is what it is for. Exercised below.
	# 29 since CLOUD-514: a row this branch filed and never groomed to Ready. It
	# sits beside the deferral stop and stops the lap the same way. Exercised below.
	# 30 since CLOUD-861: the disk filled DURING verify. It is a separate stop
	# rather than a branch inside the generic verify one because the two need
	# opposite advice — that stop says "reproduce and fix locally", which is
	# right for a refusal of this tree and wrong for an environment failure with
	# nothing in the diff to reproduce. It precedes the generic stop for the same
	# reason. Exercised below, with an anti-vacuity twin holding the narrowing to
	# its scope: an ordinary failure must still get the original advice.
	# 31 since CLOUD-862: the replay-unwind for an ADOPTED bet cannot resolve.
	# It is a second stop rather than a branch of the reset-unwind's because the
	# two fail for different reasons and only one of them is recoverable by the
	# operator — a reset that fails means the undo point is gone, a replay that
	# fails means another branch's commits will not come off, and the second is
	# the one that must never reach a push. Exercised below.
	# 33 since CLOUD-727: a `verify` failure on a SPECULATIVELY linearized tree.
	# It is a separate stop rather than a branch inside the generic verify one for
	# the reason the disk stop is: the generic arm's advice — "reproduce and fix
	# locally" — is wrong when the tree under test carries another branch's
	# unlanded commits, and it precedes that arm for the same reason. Exercised
	# below, with an anti-vacuity twin holding the narrowing to its scope: an
	# ordinary failure with no speculation must still get the original advice.
	# 32 since CLOUD-827: a prose-only branch, whose whole diff is comment lines
	# with no test change. It is the only stop here that is about what the change
	# is WORTH rather than whether it is correct — every gate above it asks
	# whether the branch works, and this one asks whether the matrix it is about
	# to buy can have an opinion about it. Exercised below, with the admitting
	# direction held by the gate's own suite rather than duplicated here.
	[ "$stops" -eq 33 ] || {
		echo "land has $stops stopping conditions; this suite covers 33."
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
	# 14 since CLOUD-495: winning the lease can now settle a bet the holder
	# abandoned, and an unwind there moved HEAD — so the lap ends rather than
	# pushing a commit this branch no longer has. Exercised below.
	# 15 since CLOUD-483: a red run whose every failed required job died before
	# reaching a verdict is re-run and lapped rather than reported. Two sessions
	# each added a lap ending and each claimed 14 — the rebase conflict here WAS
	# the sensor catching a count neither branch could see alone, which is what
	# it is for.
	[ "$laps" -eq 15 ] || {
		echo "land has $laps lap-ending continues; this suite covers 15."
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
# A holder whose head is published AND whose CI answered green — the two facts
# admission now requires. `checks-green` exit 0 is the only admitting answer, so
# every other case below states the answer it is about.
holder_is_green() {
	echo "${1:-h01dh01dh01dh01d}" >"$BATS_TEST_TMPDIR/lease.head"
	rm -f "$BATS_TEST_TMPDIR/rc.mise.checks-green"
}

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
	# NARROWED, not weakened (CLOUD-862). This read `!= *batten-spec*` — no
	# mention of the ref at all — until the recovery path started probing it once
	# per lap to settle a bet a dead run may have left. That probe is a
	# `rev-parse`: read-only, no fetch, no rebase, and it is what makes the
	# stranding detectable at all. What the row actually asserts is that no
	# SPECULATION happened, so it names the two calls that would be one.
	# PER LINE, not over the whole file. A `[[ $(cat …) != *fetch*batten-spec* ]]`
	# reads the log as one string, so an unrelated `fetch` on one line and the
	# recovery's `rev-parse` on another satisfy the glob together — it fired on
	# exactly that and said a speculation had happened when none had.
	! grep -qE '^fetch .*batten-spec' "$BATS_TEST_TMPDIR/gitlog"
	! grep -qE '^rebase' "$BATS_TEST_TMPDIR/gitlog"
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
	holder_is_green
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

@test "a verify failure on a SPECULATIVE tree names the borrowed base" {
	# CLOUD-727. `land` already holds the fact — it printed the base a few lines
	# earlier — and then emitted an unconditional message whose two sentences are
	# both wrong here: "reproduce and fix locally" points at a defect the author did
	# not write, and "CI is not where you discover this" implies discovery is overdue
	# when the tree under test is not the one the author will ever push.
	#
	# Measured 2026-08-19: a two-commit branch touching only `.serena/memories/*`
	# failed on two findings in files neither commit touched, and rebasing off the
	# speculative base was green first try. On 2026-08-22 the masked failure was in
	# `land`'s OWN suite — the most expensive possible wrong place to send someone.
	#
	# DRIVEN THROUGH THE RECOVERY PATH, because the lap's own speculation is placed
	# AFTER verify runs: a bet is adopted at the top of the lap, so `spec_base` is
	# set before the first verify rather than after it. The bet must settle as
	# PENDING — the ordinary reading, and the only one that leaves the tree
	# linearized while the lap proceeds.
	stranded
	spec_head holder-branch
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_live"
	task_fails verify
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"this tree is SPECULATIVE"* ]]
	# BOTH recoveries, because `rebase --onto` is not the only one and the cheaper
	# one is available whenever the remote still holds the clean branch.
	[[ "$output" == *"rebase --onto origin/main"* ]]
	[[ "$output" == *"reset --hard"* ]]
	# A SUSPICION, never a verdict: this row retracted two attributions in one day
	# for treating "speculative" as the explanation because it was the salient
	# difference, so the message must say how to find out rather than decide.
	[[ "$output" == *"may not be yours"* ]]
	[[ "$output" == *"If it still fails off the borrowed base, it is yours"* ]]
	# The advice that is wrong here must not also be present.
	[[ "$output" != *"Reproduce and fix locally"* ]]
}

@test "a verify failure with NO speculation still gets the original advice" {
	# The anti-vacuity twin, and what stops the fix widening a message that is
	# already right in the common case. Same failure, no borrowed base.
	task_fails verify
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Reproduce and fix locally"* ]]
	[[ "$output" != *"this tree is SPECULATIVE"* ]]
}

@test "A WAITER THAT IS NOT ADMITTED STAYS IN DRAFT — this is what bounds the cost" {
	# The negative that gives the case above its meaning. Without it, "every
	# waiter readies" would pass the test above and spend a matrix per session,
	# which is the defect the whole issue is about.
	lease_lost
	spec_head holder-branch
	holder_is_green
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
	holder_is_green
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
	holder_is_green
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=3 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$(call_order)" == "ready push"* ]]
	[ "$(grep -c '^push$' "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
	[[ "$output" == *"its run is already in flight"* ]]
}

# --- an abandoned base is not a pending one (CLOUD-495) ----------------------
#
# The unwind above fires on ONE reading of a lost bet: `main` moved and took
# something else. The holder abandoning while `main` stays put reads as *pending*
# through that predicate, and pending returns 0 forever — no lap budget, no
# re-read of who holds the lease. So the waiter keeps a borrowed tree, later wins
# the lease, and the in-hold re-confirmation asks only whether `main` moved. It
# did not. What lands is another branch's unmerged commits.
#
# The predicate that closes it: a bet is LIVE only while the branch the lease
# names *now* is somebody else's and still carries the base. Everything else —
# lease freed, lease passed on, lease won by us, lease unreadable — is stale.

# The holder lets go from the Nth acquire on. Empty means the lease freed; a name
# means it passed to that branch.
lease_abandons() {
	printf '%s' "${1-}" >"$BATS_TEST_TMPDIR/lease_abandons_to"
	echo "${2:-2}" >"$BATS_TEST_TMPDIR/lease_abandons_after"
}
bet_is_dead() { echo 1 >"$BATS_TEST_TMPDIR/rc.spec_live"; }

@test "AN ABANDONED HOLDER IS NOT A PENDING BET: the lease freed unwinds it" {
	# The hazard in one row. Nothing about `main` changes, so every reading the
	# old settle had says "the holder is still landing" — while the holder is
	# gone and the base can never land.
	lease_lost
	spec_head holder-branch
	lease_abandons ""
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"no longer the base that is about to land; unwinding"* ]]
	grep -q '^reset -q --hard cafe1234cafe1234$' "$BATS_TEST_TMPDIR/gitlog"
	# `main` never moved, which is what makes this distinct from the case above.
	[[ "$output" != *"did not land; unwinding"* ]]
	[ "$(call_order)" = "" ]
}

@test "the lease passing to a branch that does not carry our base unwinds it" {
	# The other abandonment shape: somebody else won the lease, and their head has
	# nothing to do with the commit we bet on.
	lease_lost
	spec_head holder-branch
	lease_abandons other-branch
	bet_is_dead
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"no longer the base that is about to land; unwinding"* ]]
	grep -q '^fetch -q origin +refs/heads/other-branch:refs/batten-spec/live$' "$BATS_TEST_TMPDIR/gitlog"
}

@test "A LIVE BET IS LEFT ALONE — without this, the unwind fires every lap" {
	# The negative that gives the two rows above their meaning, and the property
	# the pending arm exists for: unwinding an undecided bet would undo the
	# linearization each lap and leave the mechanism running while achieving
	# nothing. The holder still holds, and still carries the base.
	lease_lost
	spec_head holder-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" != *"unwinding"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/gitlog")" != *"reset -q --hard"* ]]
}

@test "a liveness read that fails is stale, never live — the fetch fails closed" {
	# An unreadable lease must never certify a borrowed tree. Failing open here
	# would make a network blip the thing that lands somebody else's commits.
	lease_lost
	spec_head holder-branch
	lease_abandons other-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.fetch_live"
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.reserve"
	pr_state MERGED
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"no longer the base that is about to land; unwinding"* ]]
}

@test "WINNING THE LEASE SETTLES THE BET FIRST: no borrowed tree is readied, pushed or merged" {
	# The severe case, end to end. The waiter holds a bet, the holder abandons,
	# `main` stays put — and the waiter then WINS. Holding the lease with the base
	# not yet on `main` can only mean the branch we bet on is gone, so the settle
	# inside the hold is what stops the `/fast-forward`. Merged is asserted absent
	# rather than present: nothing may be published from a borrowed tree.
	spec_head holder-branch
	echo 1 >"$BATS_TEST_TMPDIR/rc.mise.land-lock.acquire"
	lease_abandons ""
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=2 run "$LAND"
	[[ "$output" == *"no longer the base that is about to land; unwinding"* ]]
	# The unwind precedes anything that spends: no ready, no push, no comment
	# while the borrowed range was still in the tree.
	unwind=$(grep -n 'reset -q --hard' "$BATS_TEST_TMPDIR/gitlog" | head -1 | cut -d: -f1)
	[ -n "$unwind" ]
	[ "$(comments)" -eq 0 ]
}

@test "a bet already PUSHED is re-drafted before its remote is rewound" {
	# The successor publishes (`ready`, `push`), so an unwind that touched only
	# the tree would leave origin holding the foreign commits with an open PR
	# pointing at them — which is exactly the two-PRs-at-one-SHA state measured on
	# this loop. Re-draft first, so the corrective push buys no matrix: the same
	# close-the-tap-before-moving-the-ref ordering the red path already uses.
	lease_lost
	spec_head holder-branch
	holder_is_green
	lease_abandons "" 3
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=4 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"no longer the base that is about to land; unwinding"* ]]
	[[ "$output" == *"re-drafted"* ]]
	# The successor's publish (ready, push), then the re-draft and the rewinding
	# push. Both `gh pr ready` forms record as `ready`, so the ORDER is read from
	# calls and the second one's `--undo` from what it was invoked with.
	[[ "$(call_order)" == "ready push ready push"* ]]
	[ "$(grep -c -- '--undo' "$BATS_TEST_TMPDIR/ready")" -ge 1 ]
	# The corrective push is force-with-lease, like every other push this loop
	# makes: rewinding a published branch is exactly the case that ref guard is
	# for.
	grep -q 'push --force-with-lease' "$BATS_TEST_TMPDIR/gitlog"
}

# --- CLOUD-483: a red that never reached a verdict is not a verdict -----------
#
# `nonverdict-scan` owns the classification; these rows grade what `land` does
# with it. The trio is the point: absorb, refuse to absorb, and the empty case
# that a naive "every record is a nonverdict" test gets wrong by vacuity.

nonverdict_records() { printf '%s\n' "$1" >"$BATS_TEST_TMPDIR/nonverdict"; }
reruns() {
	if [ -s "$BATS_TEST_TMPDIR/reruns" ]; then grep -c . "$BATS_TEST_TMPDIR/reruns"; else echo 0; fi
}

@test "CLOUD-483: a run that died before any mise step is re-run, not reported red" {
	# Measured on #376: commit-lint died in the toolchain setup step, so it
	# never linted a commit — and `land` sent the agent to reproduce a failure that
	# passes locally. `gh run rerun --failed` re-queued that one job; a fresh push
	# would have bought the whole matrix.
	nonverdict_records "nonverdict	run=4242	job=commit-lint	step=Run jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654"
	task_fails ci-wait
	run "$LAND"
	[[ "$output" != *"verify and CI disagree"* ]]
	[[ "$output" == *"before reaching a verdict"* ]]
	[ "$(reruns)" -ge 1 ]
}

@test "CLOUD-483: a job that reached a verdict is red, and is never re-run" {
	# The anti-regression half. A change that re-ran unconditionally would pass the
	# row above and re-run every genuine failure until its budget ran out.
	nonverdict_records "verdict	run=4242	job=ci	step=Run mise run ci"
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
	[ "$(reruns)" -eq 0 ]
}

# --- abandoning the matrix on a genuine red (CLOUD-900) ---------------------
#
# `land` is the one call site: `checks-green` has already decided by the time the
# red arm is reached, so re-deriving the verdict anywhere else would be a second
# authority for one fact. What these cases pin is the ORDERING inside that arm —
# which of the three things arriving there may spend a cancellation. The task's
# own behaviour is `tests/abandon-matrix.bats`; here only the call is asserted,
# through the `mise` stub that records every task a lap runs.

abandons() { grep -c '^run abandon-matrix' "$BATS_TEST_TMPDIR/misecalls" || true; }

@test "CLOUD-900: a genuine red abandons the rest of the matrix" {
	# The acceptance case. Past the lease test and past the transient test, the
	# failure is an answer about the tree — so every sibling still running is
	# spending to re-learn a verdict that is already in.
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
	[ "$(abandons)" -ge 1 ]
}

@test "CLOUD-900: a run CI DECLINED abandons nothing — it is not a verdict" {
	# The lease arm (CLOUD-470). Nothing about this branch is broken: the run was
	# cancelled because another branch holds the lease, and the remedy is a
	# rebase. Cancelling its siblings would spend the fleet a matrix to punish a
	# branch that did nothing wrong, and the next lap needs those runs.
	lease_declines
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CANCELLED"* ]]
	[ "$(abandons)" -eq 0 ]
}

@test "CLOUD-900: a provisioning transient abandons nothing — the jobs get re-run" {
	# THE ROW THAT DECIDED THE DESIGN. `gh run rerun --failed` re-queues the
	# failed jobs OF A RUN; nothing restores a sibling run that was cancelled. So
	# abandoning here would convert a one-job re-run into a fresh matrix, making
	# the transient path strictly more expensive than before the saving existed.
	#
	# This is also why the call sits in `land` rather than in each failing job: a
	# job that dies in provisioning cannot tell that it did, and would abandon on
	# its way out.
	nonverdict_records "nonverdict	run=4242	job=commit-lint	step=Run jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654"
	task_fails ci-wait
	run "$LAND"
	[[ "$output" == *"before reaching a verdict"* ]]
	[ "$(abandons)" -eq 0 ]
}

@test "CLOUD-900: a lap CI answered green abandons nothing" {
	# The discriminating half, and the partner of `a lap that CI answered cancels
	# nothing` above: a green run is the one thing worth paying out in full.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[ "$(abandons)" -eq 0 ]
}

@test "CLOUD-483: EMPTY IS NOT UNANIMOUS — no records is red, not absorbed" {
	# The vacuity case. "Every record is a nonverdict" is trivially true of no
	# records at all, which is what an unreadable payload, a roster miss, or a
	# failure confined to the `final` fan-in each produce. Absorbing that would
	# re-run a genuinely red branch until the budget ran out, with no evidence
	# that anything was transient.
	nonverdict_records ""
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CI is red"* ]]
	[ "$(reruns)" -eq 0 ]
}

@test "CLOUD-483: the retry budget is a COUNT, and exhausting it stops" {
	# Three in a row is a broken provisioning path, not a flake — and re-running
	# again would spend jobs to learn the same thing. A count, never a clock: the
	# no-wall-clock sensor below must keep passing.
	nonverdict_records "nonverdict	run=4242	job=ci	step=Run actions/checkout@3d3c42e"
	task_fails ci-wait
	LAND_MAX_TRANSIENTS=1 run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not a flake any more"* ]]
}

@test "CLOUD-483: a re-run the API refuses stops, naming the command" {
	# The absorbed path depends on a write succeeding. If it does not, laping
	# would poll the same red forever, so this stops and hands over the one
	# command that fixes it.
	nonverdict_records "nonverdict	run=4242	job=ci	step=Run actions/checkout@3d3c42e"
	: >"$BATS_TEST_TMPDIR/rc.rerun"
	task_fails ci-wait
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"re-running run"* ]]
	[[ "$output" == *"gh run rerun"* ]]
}

# --- CLOUD-383: the race waits without bash 4 --------------------------------

# Fails the Nth `mkfifo`, so a case can reach the SECOND race's rendezvous — the
# first one succeeding is what gets the lap as far as the CI wait.
mkfifo_fails_on() {
	cat >"$STUB/mkfifo" <<EOF
#!/usr/bin/env bash
n=\$(cat "$BATS_TEST_TMPDIR/mkfifo.calls" 2>/dev/null || echo 0)
n=\$((n + 1)); echo "\$n" >"$BATS_TEST_TMPDIR/mkfifo.calls"
[ "\$n" != "$1" ] || exit 1
exec /usr/bin/mkfifo "\$@"
EOF
	chmod +x "$STUB/mkfifo"
}

@test "CLOUD-383: a rendezvous that cannot be created stops, rather than guessing" {
	# The race decides the lap: whichever of verify and main-watch answers first
	# ends it, and the loser's EMPTY rc file is what says it never finished. With
	# no rendezvous there is nothing to wait on, so both rc files would read empty
	# and the lap would report "no verdict" over a race that never ran.
	mkfifo_fails_on 1
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rendezvous for verify"* ]]
}

@test "CLOUD-383: the CI wait's rendezvous stops too, at top level" {
	# The second call site, and the reason there are two stops rather than one:
	# `new_rendezvous` returns its failure instead of dying, so each caller must
	# die itself. A `die` inside the command substitution would exit the subshell
	# and the lap would continue with an empty path — which is exactly what the
	# first cut of this did, and what CLOUD-467 warned about in this same file.
	mkfifo_fails_on 2
	pr_state OPEN
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rendezvous for the CI wait"* ]]
}

@test "CLOUD-383: the races carry no bash-4 construct" {
	# THE PORTABILITY PROPERTY, structural because no suite running on bash 5 can
	# observe it. `wait -n` needs 4.3 and its PID-list form needs 5.1; macOS ships
	# 3.2 as /bin/bash and `mise registry` carries no bash, so a single executable
	# `wait -n` here is `land` being unrunnable on a platform `darwin-link` makes
	# a required check. Prose mentions are exempt: the ban is on running it.
	run grep -cE '^[[:space:]]*wait -n' "$REAL_LAND"
	[ "$output" -eq 0 ]
	# And the rendezvous it was replaced with is really there, so this row cannot
	# pass by the races having been deleted.
	run grep -c 'await_first' "$REAL_LAND"
	[ "$output" -ge 2 ]
}

# --- CLOUD-518: the webhook subscription the harness arms on every PR ----------
#
# `land` DOES drop it now (CLOUD-790). The 401 this block used to cite was a
# missing `Authorization` header, not a missing credential: with the container's
# session-ingress token as a bearer, `POST /v2/ccr-sessions/<id>/github/mcp`
# serves `unsubscribe_pr_activity`. So `drop` runs first and `check` still
# decides, because `drop` fails open on everything it cannot establish and the
# agent's manual `record` remains the way through when it does.
#
# The gate's own suite (tests/pr-unsubscribed.bats) covers both the recording and
# the actor; these rows are about the LANDING: that the drop is attempted for THIS
# PR on every lap, that the refusal stops the lap before anything is spent, and
# that a dropped subscription lets a landing proceed.
#
# Every other case in this file leaves `pr-unsubscribed` passing, which is both
# the off-harness reading and the ordinary one — so nothing else in the suite is
# perturbed by putting a gate on the critical path.

@test "CLOUD-518: a session that has not dropped the subscription cannot land" {
	# The refusal the whole change exists to produce. It must arrive BEFORE any
	# spend: no ready, no push, no comment, and no CI.
	#
	# THE WORLD IS TERMINAL AND THE RUN IS BOUNDED, both so that the MUTATION
	# fails this row instead of hanging it. With the check disabled the lap runs
	# on, and `main-watch` never answers by default — so a row written as a bare
	# `run "$LAND"` blocks forever rather than going red, which is a mutation
	# reported as caught by a case that never finished. Measured: wedged for 100
	# minutes inside `mise run mutant`. `pr_state MERGED` gives the un-gated path
	# a fast, wrong ending; `run_timeout` is the backstop if it finds another way
	# to stall.
	task_fails pr-unsubscribed
	pr_state MERGED
	local out="$BATS_TEST_TMPDIR/land.out" rc=0
	run_timeout -k 1 20 "$LAND" >"$out" 2>&1 || rc=$?
	output=$(cat "$out")
	status=$rc
	[ "$status" -eq 1 ]
	[[ "$output" == *"webhook subscription has not been dropped"* ]]
	# Nothing was spent: the PR was never readied, nothing was pushed, and the
	# fast-forward was never asked for.
	[ -z "$(ready_calls)" ]
	[[ "$(call_order)" != *push* ]]
	[ "$(comments)" -eq 0 ]
	# Not even the verify receipt was consulted — the stop is the first thing.
	[ "$(verify_calls)" -eq 0 ]
}

@test "CLOUD-518: the check runs against THIS PR, not some other" {
	# A receipt for the wrong pull request is the honest error the gate is built
	# for, so `land` has to hand it the PR it is actually landing.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	run grep -c '^run pr-unsubscribed check 150$' "$BATS_TEST_TMPDIR/misecalls"
	[ "$output" -ge 1 ]
}

@test "CLOUD-790: the landing makes the unsubscribe call itself, for THIS PR" {
	# The click this removes. Before CLOUD-790 the only way to satisfy the gate
	# below was an agent tool call the connector sets to `always_ask` — one human
	# approval per landing, against a subscription the harness armed with none.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	run grep -c '^run pr-unsubscribed drop 150$' "$BATS_TEST_TMPDIR/misecalls"
	[ "$output" -ge 1 ]
}

@test "CLOUD-790: a drop that could not happen does not stop the landing itself" {
	# `drop` fails open, so a session that cannot reach the endpoint must land
	# exactly as it did before — refused by `check`, not by the actor in front of
	# it. An actor that could refuse would be a second way to wedge a landing.
	task_fails pr-unsubscribed
	pr_state MERGED
	local out="$BATS_TEST_TMPDIR/land.out" rc=0
	run_timeout -k 1 20 "$LAND" >"$out" 2>&1 || rc=$?
	output=$(cat "$out")
	status=$rc
	[ "$status" -eq 1 ]
	# The refusal is the GATE's, naming the receipt — not a failure of the drop.
	[[ "$output" == *"webhook subscription has not been dropped"* ]]
}

@test "CLOUD-518: a dropped subscription lets the landing proceed untouched" {
	# The gate passing must change nothing else about a lap — the same merge, the
	# same single fast-forward comment.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
	[ "$(comments)" -eq 1 ]
}

# --- admission is conditioned, not automatic (CLOUD-369) ---------------------
#
# The second matrix is a favourable bet BECAUSE it is conditioned. A holder that
# is green and holds the lease will almost certainly fast-forward, so the
# successor's run overlaps a merge that is about to happen. Bought behind a
# holder whose CI has not answered, the same run is voided the moment that holder
# goes red — an extra matrix spent to save nothing, which is the waste this issue
# exists to remove reappearing inside its own fix.
#
# The cases below are the NEGATIVES. Their absence is precisely why the clause
# was dropped unnoticed the first time: tests written from the implementation can
# only confirm it, and a dropped condition has no code to write a test against.

@test "CLOUD-369 clause b1-neg — a holder whose CI answers RED admits nobody" {
	lease_lost
	spec_head holder-branch
	holder_is_green
	head_verdict 1
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"has not gone green"* ]]
	[[ "$output" != *"admitted as the successor"* ]]
	[ "$(lock_calls reserve)" -eq 0 ]
	[ "$(call_order)" = "" ]
}

@test "CLOUD-369 clause b1-neg — a holder whose CI has NOT ANSWERED admits nobody" {
	# Exit 3 is "no answer yet", the commonest reading of all: the holder has
	# only just pushed. Not yet is the safe direction — declining costs one poll.
	lease_lost
	spec_head holder-branch
	holder_is_green
	head_verdict 3
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"has not gone green"* ]]
	[ "$(lock_calls reserve)" -eq 0 ]
	[ "$(call_order)" = "" ]
}

@test "CLOUD-369 clause b1-neg — a holder whose CI COULD NOT BE READ admits nobody" {
	# Exit 2 is "could not look". This gate declines rather than failing open:
	# waving a matrix through on an unreadable answer spends money on a guess,
	# and the cost of declining is one poll.
	lease_lost
	spec_head holder-branch
	holder_is_green
	head_verdict 2
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"has not gone green"* ]]
	[ "$(lock_calls reserve)" -eq 0 ]
}

@test "CLOUD-369 clause b1-neg — a lease naming no head admits nobody" {
	# Every lease minted before the `head:` field is exactly this, so during any
	# rollout the row is not an edge case. The holder's CI cannot be read at all,
	# which is not the same as red and is reported as its own reason.
	lease_lost
	spec_head holder-branch
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"names no head"* ]]
	[ "$(lock_calls reserve)" -eq 0 ]
	[ "$(call_order)" = "" ]
}

@test "CLOUD-369 clause b1-pos — a GREEN holder still admits exactly one waiter" {
	# The positive the negatives give meaning to. A conditioning that also stopped
	# admitting green holders would pass every case above and deliver nothing.
	lease_lost
	spec_head holder-branch
	holder_is_green
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"admitted as the successor behind a green holder"* ]]
	[ "$(lock_calls reserve)" -eq 1 ]
	[[ "$(call_order)" == "ready push"* ]]
}

@test "CLOUD-369 clause e — a waiter whose base CONFLICTS is not admitted" {
	# The conflict `speculate` already computed, now spent on the admission
	# rather than discarded. A base that will not apply guarantees the run is
	# voided: it grades a head the fast-forward refuses, and the rebase that
	# follows still has to resolve the same conflict.
	lease_lost
	spec_head holder-branch
	holder_is_green
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_rebase"
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"could never pay"* ]]
	[[ "$output" != *"admitted as the successor"* ]]
	[ "$(lock_calls reserve)" -eq 0 ]
	[ "$(call_order)" = "" ]
}

@test "CLOUD-369 clause e — a waiter whose base APPLIES CLEANLY still is admitted" {
	# The negative of the negative: a conflict arm that refused everyone would
	# pass the case above and silently delete the whole mechanism.
	lease_lost
	spec_head holder-branch
	holder_is_green
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_rebase"
	is_draft
	pr_state OPEN
	LAND_LOCK_MAX_WAITS=1 run "$LAND"
	[ "$status" -eq 4 ]
	[[ "$output" == *"admitted as the successor"* ]]
	[ "$(lock_calls reserve)" -eq 1 ]
}

# --- CLOUD-861: a full disk is the environment, not a verdict on this tree ----

@test "CLOUD-861: an ENOSPC during verify is reported as the environment, not as a defect to reproduce" {
	# THE DISCRIMINATING ROW, and it is red against `land` as it stood on
	# 2026-08-21. Measured that day: `target-prune` passed the lap with 6242MB
	# against its 4096MB floor, the `cargo test` link step then consumed all of
	# it, and the stop said "verify failed ... Reproduce and fix locally" over a
	# tree with nothing wrong in it. The advice is correct for a real refusal and
	# actively misleading for this one — the same misattribution CLOUD-811
	# records in `linear-check`.
	task_fails verify
	printf '%s\n' \
		'[hooks] test - rustc-LLVM ERROR: IO failure on output stream: No space left on device' \
		>"$BATS_TEST_TMPDIR/rc.mise.verify.says"
	run "$LAND"
	[ "$status" -eq 1 ]
	# Named as the environment, with the reclaim to run.
	[[ "$output" == *"the disk filled"* ]]
	[[ "$output" == *"target-prune"* ]]
	[[ "$output" == *"incremental"* ]]
	# And NOT as this branch's defect. This is the assertion that fails today.
	[[ "$output" != *"Reproduce and fix locally"* ]]
	# Still a stop on lap 1, not a retry loop into the backstop: the disk does
	# not empty itself, so lapping would spend the budget re-hitting the wall.
	[ "$(verify_calls)" -eq 1 ]
	[ "$(comments)" -eq 0 ]
}

@test "an ordinary verify failure still says reproduce it locally" {
	# ANTI-VACUITY. The row above is a narrowing, and a narrowing that swallowed
	# the general case would turn every refusal into "check your disk" — which
	# is CLOUD-811's defect rebuilt facing the other way. A failure carrying no
	# ENOSPC line keeps the advice that is right for it.
	task_fails verify
	printf '%s\n' \
		'[hooks] crates/batten/tests/primitives.rs:1171 no-consumer-repo-name' \
		>"$BATS_TEST_TMPDIR/rc.mise.verify.says"
	run "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Reproduce and fix locally"* ]]
	[[ "$output" != *"the disk filled"* ]]
}

# --- CLOUD-862: a bet the process that placed it never settled ---------------
#
# The measured incident: a `land` speculated onto a sibling branch's head, was
# stopped before it could settle, and the NEXT `land` ran a full clean `verify`
# and reached the push carrying seven of that branch's unlanded commits. The
# state was on disk the whole time; `settle_speculation` opened on a shell
# variable and so never looked.
#
# `stranded` is the lever the suite lacked: a bet ref present with no in-process
# state behind it, which is exactly what a killed run leaves.
stranded() {
	echo 5peccccc5peccccc >"$BATS_TEST_TMPDIR/specbet"
	# The tree IS built on the adopted base — it was rebased onto it before the
	# run died. Without this the ref is stale rather than stranded, and the two
	# must not be confused.
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_ontree"
}

@test "CLOUD-862: a bet left by a dead run is adopted and unwound before anything is pushed" {
	# THE DISCRIMINATING ROW. Red against `land` without the recovery: with no
	# `spec_base` set in this process, settle returned 0 on its first line and
	# the borrowed range rode all the way to the push.
	stranded
	bet_is_dead
	pr_state MERGED
	run "$LAND"
	[[ "$output" == *"adopting an unsettled speculation"* ]]
	[[ "$output" == *"no longer landing"* ]]
	# Unwound by REPLAY, not by reset: an adopted bet has no undo point, and the
	# base is all that is needed to put this branch's own commits back on main.
	grep -q '^rebase --onto origin/main 5peccccc5peccccc$' "$BATS_TEST_TMPDIR/gitlog"
	# And the ref is gone, so the next run does not adopt it a second time.
	[ ! -f "$BATS_TEST_TMPDIR/specbet" ]
}

@test "CLOUD-862: an adopted bet whose base LANDED keeps the tree and just drops the ref" {
	# ANTI-VACUITY, and the reading that stops the fix being "never speculate".
	# The holder landed while nobody was watching, so the linearization was
	# correct all along and unwinding it would throw away a warm tree for nothing.
	stranded
	echo 0 >"$BATS_TEST_TMPDIR/rc.spec_landed"
	pr_state MERGED
	run "$LAND"
	[[ "$output" == *"the speculation landed"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/gitlog")" != *"rebase --onto origin/main"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/specbet" ]
}

@test "CLOUD-862: a bet ref naming a commit this tree is not built on is dropped, not acted on" {
	# The third reading, and the one that keeps the ref honest rather than
	# merely present: a ref left by a clone that reset names a base this HEAD
	# never carried. Adopting it would replay off a commit that is not in the
	# history and take this branch's own work with it.
	echo 5peccccc5peccccc >"$BATS_TEST_TMPDIR/specbet"
	echo 1 >"$BATS_TEST_TMPDIR/rc.spec_ontree"
	pr_state MERGED
	run "$LAND"
	[[ "$output" != *"adopting an unsettled speculation"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/gitlog")" != *"rebase --onto origin/main"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/specbet" ]
}

@test "a run with no bet ref is untouched by the recovery path" {
	# ANTI-VACUITY for the whole mechanism: the ordinary land, which is every
	# land, must not pay for or notice any of this.
	pr_state MERGED
	run "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" != *"adopting an unsettled speculation"* ]]
}
