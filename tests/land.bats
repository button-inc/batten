#!/usr/bin/env bats
# land's two exit conditions, exercised through a stub `gh`.
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

setup() {
	LAND="$BATS_TEST_DIRNAME/../mise-tasks/land"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	# A short interval keeps the polling cases quick; PR is supplied so the
	# stub never has to answer the "which PR" lookup.
	export PATH PR=150 LAND_INTERVAL=1
	: >"$BATS_TEST_TMPDIR/comments"
	stub_gh
	stub_git
	pr_state OPEN
	workflow_runs runs.last
}

# A fake `gh` covering the three calls land makes. `--jq` is applied with the
# real jq to a real JSON body, so a filter that stops matching fails here.
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
case "\$sub" in
  "pr comment")
    echo "\$all" >>"$BATS_TEST_TMPDIR/comments"; echo commented ;;
  "pr view")
    emit "\$(cat "$BATS_TEST_TMPDIR/state")" ;;
  api*)
    case "\$url" in
      # The truth the old implementation got wrong: the bot's run is not here.
      *commits/*check-runs*) emit '{"check_runs":[]}' ;;
      *actions/workflows/*)
        n=\$(cat "$BATS_TEST_TMPDIR/runcalls" 2>/dev/null || echo 0)
        echo \$((n + 1)) >"$BATS_TEST_TMPDIR/runcalls"
        body=\$(cat "$BATS_TEST_TMPDIR/runs.\$((n + 1))" 2>/dev/null || cat "$BATS_TEST_TMPDIR/runs.last")
        emit "\$body" ;;
      *) emit '{}' ;;
    esac ;;
esac
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/runcalls"
}

# `git` is stubbed too: land resolves HEAD, and fetches main once the PR closes.
stub_git() {
	cat >"$STUB/git" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "rev-parse HEAD")     echo cafe1234cafe1234 ;;
  "rev-parse --short"*) echo abc1234 ;;
  *)                    exit 0 ;;
esac
EOF
	chmod +x "$STUB/git"
}

pr_state() { printf '{"state":"%s"}' "$1" >"$BATS_TEST_TMPDIR/state"; }

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

@test "a refusal exits non-zero and names the remedy" {
	# The regression this file exists for. Note the check-runs endpoint is
	# empty throughout, as it is in reality — so the pre-CLOUD-235 filter
	# cannot pass this test, it can only hang.
	workflow_runs runs.last failure
	run timeout 20 "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"the fast-forward bot refused (failure)"* ]]
	[[ "$output" == *"Rebase, re-verify, retry"* ]]
}

@test "a cancelled run is a refusal too, not just a failure" {
	workflow_runs runs.last cancelled
	run timeout 20 "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"refused (cancelled)"* ]]
}

@test "a merged PR exits 0" {
	pr_state MERGED
	run timeout 20 "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
}

@test "a PR that closed without merging exits non-zero" {
	pr_state CLOSED
	run timeout 20 "$LAND"
	[ "$status" -eq 1 ]
	[[ "$output" == *"is CLOSED"* ]]
}

@test "a run still in progress concludes neither way, and the poll continues" {
	# Queued or running is not an answer. Concluding early in either direction
	# is the failure — a premature success reports a landing that never happened.
	workflow_runs runs.1
	workflow_runs runs.2
	workflow_runs runs.last failure
	run timeout 20 "$LAND"
	[ "$status" -eq 1 ]
	[ "$(cat "$BATS_TEST_TMPDIR/runcalls")" -ge 3 ]
}

@test "a run that predates this attempt is not read as a verdict on it" {
	# An earlier landing of the same PR, refused and since rebased, leaves a
	# failed run behind forever. Reading it would make every later attempt
	# report a refusal that already happened — so the window is stamped before
	# commenting, and this asserts the stamp is load-bearing rather than decor.
	workflow_runs runs.1 failure 2000-01-01T00:00:00Z
	workflow_runs runs.2 failure 2000-01-01T00:00:00Z
	workflow_runs runs.last failure 2000-01-01T00:00:00Z
	pr_state OPEN
	{
		sleep 3
		pr_state MERGED
	} &
	run timeout 20 "$LAND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"is MERGED"* ]]
}

@test "the merge is what it waits for, not the comment" {
	# A comment plus a guessed sleep is the shape this task replaces: the
	# comment only *starts* the landing.
	workflow_runs runs.last
	{
		sleep 3
		pr_state MERGED
	} &
	run timeout 20 "$LAND"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$BATS_TEST_TMPDIR/comments")" -eq 1 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/comments")" == *"/fast-forward"* ]]
}

@test "the poll carries no wall-clock timeout" {
	# A hang is fixed by an exit condition that can fire, never by capping the
	# poll — a cap reintroduces the VM-reap gap and would land as a false
	# "refused" on a slow bot.
	run grep -cE '\btimeout [0-9]' "$LAND"
	[ "$output" -eq 0 ]
}
