#!/usr/bin/env bats
# subject: mise-tasks/stop-guard.sh
# The Stop hook body: one bounded re-prompt per turn, and fail-open everywhere
# else. CLOUD-187 is why this suite carries the wiring assertion too — a hook that
# lands mid-session is not in that session's wiring, so the suite is the only
# in-session proof that the entry exists at all.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/stop-guard.sh"
	SETTINGS="$BATS_TEST_DIRNAME/../.claude/settings.json"
	cd "$BATS_TEST_DIRNAME/.." || return 1
	# THE THIRD RULE READS REPO STATE, NOT THE MESSAGE (CLOUD-774), and these cases
	# run inside this checkout — so a punt row filed by the session running the
	# suite would make every silence assertion below flap. Off by default through
	# the gate's own bypass, and turned back on explicitly by the cases that are
	# about it, which run against a throwaway repo instead.
	export BATTEN_FILED_HERE_BYPASS=1
	# The OVERLAP hatch is the OTHER half of that gate and no case here wants it,
	# so it is cleared rather than exported: inherited, it silences the overlap
	# refusal the punt cases below are entirely about, and they go green while
	# proving nothing. Not hypothetical — `BATTEN_FILED_HERE_OVERLAP=1 mise run
	# land` is `filed-here-check`'s own remedy 4, and `land` runs `verify`, which
	# runs this suite. Same lesson as `tests/filed-here-check.bats`'s setup.
	unset BATTEN_FILED_HERE_OVERLAP
	# THE FOURTH RULE READS THE STORE AND PAYS FOR IT (CLOUD-97), and the same
	# argument applies twice over: these cases run inside this checkout, which is
	# routinely unlanded while the suite runs, and the recorder that feeds the rule
	# is a tree walk plus a store write per invocation. Off by default through the
	# gate's own bypass — which the recorder rides, so switching the rule off does
	# not leave the walk being paid for an answer nobody reads — and turned back on
	# explicitly by the cases that are about it, against a stub.
	export BATTEN_UNLANDED_CHECK_BYPASS=1
}

# `punt_repo <recorded-path>` — a throwaway repo carrying one filed row that names
# a path the branch changes, which is the state the third rule exists to see.
punt_repo() {
	local repo="$BATS_TEST_TMPDIR/punt"
	rm -rf "$repo"
	mkdir -p "$repo/a" "$repo/.git"
	git -C "$repo" init --quiet --initial-branch=work
	git -C "$repo" config user.email t@example.com
	git -C "$repo" config user.name t
	printf 'x\n' >"$repo/a/one.rs"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m base
	git -C "$repo" update-ref refs/remotes/origin/main HEAD
	printf 'changed\n' >>"$repo/a/one.rs"
	git -C "$repo" commit -q -am change
	mkdir -p "$repo/.git/batten-receipts"
	printf 'issue CLOUD-900 2026-08-19T00:00:00.000Z ready 1 a/one.rs\n' \
		>"$repo/.git/batten-receipts/board-writes.work"
	printf '%s' "$repo"
}

# The real payload shape, captured from two live Stop invocations: 11 keys, of
# which this guard reads exactly two.
stop() {
	jq -nc --arg m "$1" --argjson active "${2:-false}" \
		'{hook_event_name: "Stop", session_id: "s", cwd: ".",
		  transcript_path: "/nonexistent.jsonl",
		  stop_hook_active: $active, last_assistant_message: $m}' | "$GUARD"
}

kicked() {
	[[ "$1" == *'"additionalContext"'* ]]
}

@test "a turn whose final message carries the tell is kicked" {
	run stop 'The rebase is clean. Worth noting that the lock file still drifts.'
	kicked "$output"
	[ "$status" -eq 0 ]
}

@test "the kick names the rule and the durable destination" {
	run stop 'Worth noting the receipt is stale.'
	[[ "$output" == *"hedged-flag-framing"* ]]
	[[ "$output" == *"CLOUD-"* ]]
}

@test "the kick declares the Stop event, so the harness routes it as feedback" {
	run stop 'Worth noting one thing.'
	[[ "$output" == *'"hookEventName"'* ]]
	[[ "$output" == *'"Stop"'* ]]
}

@test "the kick is valid JSON on stdout" {
	run bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Worth noting the drift.\"}' | $GUARD | jq -e .hookSpecificOutput.additionalContext"
	[ "$status" -eq 0 ]
}

# --- exactly once ------------------------------------------------------------

@test "the re-entry caused by a previous kick is not kicked again" {
	# This is the whole of "exactly once": no state file, no cursor. The same
	# message that fires on the first Stop must be silent when the harness reports
	# it is already continuing because of one.
	run stop 'Worth noting the receipt is stale.' true
	! kicked "$output"
	[ -z "$output" ]
	[ "$status" -eq 0 ]
}

@test "the recursion bound survives a garbage stop_hook_active rather than proceeding" {
	# The inverse spelling (`!= "true"` then proceed) runs the predicate on
	# unparseable input, which defeats the bound down to the harness cap of 8.
	run bash -c "printf 'not json at all' | $GUARD"
	! kicked "$output"
	[ "$status" -eq 0 ]
}

# --- failure posture ---------------------------------------------------------

@test "a clean final message gets the closing question and nothing else" {
	# THE CONTRACT THAT CHANGED (CLOUD-97). This case asserted SILENCE, and
	# silence is the common case — which made the most valuable question the one
	# never asked. Every rule in this file fires only on a shape somebody
	# enumerated, and measured recall is the weak half of all of them; the bare
	# question has no recall problem, and `finding-sink-check`'s header records
	# it surfacing nine real findings in one session while carrying no
	# information at all.
	#
	# What must still hold is that it is the ONLY thing said: a turn with nothing
	# specific to point at must not also collect a pointer.
	run stop 'Landed on main by fast-forward, CI green.'
	kicked "$output"
	[[ "$output" == *'"additionalContext":"done?"'* ]]
	[ "$status" -eq 0 ]
}

@test "an absent last_assistant_message still ends in the closing question" {
	# It costs the FIRST rule, whose input it is, and nothing else — the rules
	# below read the transcript and the store, and the question reads neither. A
	# turn that ended without a text block is still a turn that ended.
	run bash -c "jq -nc '{stop_hook_active:false}' | $GUARD"
	[[ "$output" == *'"additionalContext":"done?"'* ]]
	[ "$status" -eq 0 ]
}

@test "the bypass is honoured" {
	# The whole registration, the closing question included: a bypass that still
	# spoke would not be one.
	BATTEN_STOP_GUARD_BYPASS=1 run stop 'Worth noting the receipt is stale.'
	! kicked "$output"
	[ -z "$output" ]
}

@test "the guard never exits non-zero, so it cannot surface as a hook error" {
	# Exit 2 is the launcher Stop hook's channel at this same boundary; two hooks
	# both exiting 2 would stack error notices on one turn.
	run stop 'Worth noting the receipt is stale.'
	[ "$status" -eq 0 ]
	run stop 'Nothing to flag here.'
	[ "$status" -eq 0 ]
}

# --- the second rule: the stranded finding (CLOUD-252) ------------------------
#
# `hedged-flag-framing` reads the final message; this one reads the transcript and
# reaches prose that field cannot carry. One advisory per turn, the shipped rule
# first.

# A payload carrying a real transcript path. The turn below strands a finding.
stranded() {
	local t="$BATS_TEST_TMPDIR/stranded.jsonl"
	: >"$t"
	jq -nc '{type:"user",isSidechain:false,message:{content:"go"}}' >>"$t"
	jq -nc --arg x "$1" '{type:"assistant",isSidechain:false,message:{content:[{type:"text",text:$x}]}}' >>"$t"
	jq -nc --arg m "${2:-Pushed and green.}" --arg p "$t" \
		'{hook_event_name:"Stop", session_id:"s", cwd:".",
		  transcript_path:$p, stop_hook_active:false, last_assistant_message:$m}' | "$GUARD"
}

@test "a turn that strands a finding is pointed at, and the turn still ends" {
	run stranded 'The wiring is missing at mise-tasks/stop-guard.sh:55.'
	[ "$status" -eq 0 ]
	kicked "$output"
	[[ "$output" == *"turn:1"* ]]
	[[ "$output" == *"finding-without-durable-write"* ]]
}

@test "POINTER, NEVER PAYLOAD: the advisory carries no byte of the turn's prose" {
	# The design in one assertion. Returning the prose makes this a mirror, and a
	# mirror is cleared by restating — the double-write CLOUD-200 and CLOUD-248
	# exist to kill. A coordinate can only be answered by going to look.
	run stranded 'Broken at mise-tasks/land.sh:200 and SENTINELXYZZY marks it.'
	[[ "$output" != *"SENTINELXYZZY"* ]]
	[[ "$output" != *"Broken at"* ]]
}

@test "the advisory says what to do, since a coordinate alone is not an instruction" {
	run stranded 'Broken at mise-tasks/land.sh:200.'
	[[ "$output" == *"file it"* ]]
}

@test "the shipped rule keeps precedence when both would fire" {
	# One nudge per turn. Two is how a channel stops being read, and the enforcing
	# rule has the higher measured precision.
	run stranded 'Broken at mise-tasks/land.sh:200.' 'Worth noting the receipt is stale.'
	[[ "$output" == *"hedged-flag-framing"* ]]
	[[ "$output" != *"finding-without-durable-write"* ]]
}

@test "a turn that strands nothing falls through to the closing question" {
	# What this case is about is that the SECOND rule stayed quiet, which is now
	# asserted directly rather than through the absence of all output.
	run stranded 'Rebased, pushed, and the gate is green.'
	[ "$status" -eq 0 ]
	[[ "$output" != *"finding-without-durable-write"* ]]
	[[ "$output" == *'"additionalContext":"done?"'* ]]
}

@test "an unreadable transcript manufactures no advisory" {
	# Fail open, like every other path in this guard: a missing file must not
	# manufacture an advisory. The closing question is not one — it is asked of
	# every turn that earned no pointer, and asking it needs no transcript.
	run stop 'Pushed and green.'
	[ "$status" -eq 0 ]
	[[ "$output" != *"finding-without-durable-write"* ]]
	[[ "$output" == *'"additionalContext":"done?"'* ]]
}

@test "the recursion bound still holds for the second rule" {
	local t="$BATS_TEST_TMPDIR/active.jsonl"
	: >"$t"
	jq -nc '{type:"user",isSidechain:false,message:{content:"go"}}' >>"$t"
	jq -nc '{type:"assistant",isSidechain:false,message:{content:[{type:"text",text:"Broken at mise-tasks/land.sh:200."}]}}' >>"$t"
	run bash -c "jq -nc --arg p '$t' '{hook_event_name:\"Stop\",session_id:\"s\",cwd:\".\",transcript_path:\$p,stop_hook_active:true,last_assistant_message:\"x\"}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- wiring ------------------------------------------------------------------

@test "the Stop hook is registered in settings" {
	# The SHAPE, not merely the name (CLOUD-479). The old assertion matched the
	# substring `stop-guard`, which `mise run -q stop-guard` and a by-path
	# registration satisfy identically — so it proved nothing about the one thing
	# that changed, and would have stayed green through a silent revert to the
	# ~194ms/call invocation.
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
cmds = [h['command'] for g in d['hooks']['Stop'] for h in g['hooks']]
entry = [c for c in cmds if 'stop-guard' in c]
assert entry, cmds
assert entry[0].endswith('/mise-tasks/stop-guard.sh'), entry
assert 'mise run' not in entry[0], entry
print('registered')"
	[ "$status" -eq 0 ]
	[[ "$output" == *"registered"* ]]
}

@test "the Stop entry declares no matcher, which the event does not support" {
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
for g in d['hooks']['Stop']:
    assert 'matcher' not in g, g
print('no matcher')"
	[ "$status" -eq 0 ]
}

# --- the punt rule (CLOUD-774) -------------------------------------------------

@test "A FILED ROW NAMING THIS BRANCH'S OWN DIFF IS POINTED AT, BEFORE ANY CI" {
	repo=$(punt_repo)
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-900"* ]]
	[[ "$output" == *"a/one.rs"* ]]
}

# POINTER, NEVER PAYLOAD — the same assertion the other two rules carry.
@test "the punt pointer carries no prose from the row" {
	repo=$(punt_repo)
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[[ "$output" != *"2026-08-19"* ]]
	[[ "$output" != *"ready"* ]]
}

# ONE ADVISORY PER TURN, and this rule is last: a turn that also carries the
# hedged-flag tell gets that one and not both.
@test "the punt rule yields to the measured posture rule" {
	repo=$(punt_repo)
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'One thing I would flag: the retry budget looks wrong.'
	[[ "$output" != *"CLOUD-900"* ]]
}

@test "a branch with no filed row names none" {
	repo=$(punt_repo)
	rm "$repo/.git/batten-receipts/board-writes.work"
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[ "$status" -eq 0 ]
	[[ "$output" != *"CLOUD-"* ]]
	[[ "$output" == *'"additionalContext":"done?"'* ]]
}

# ONCE PER ROW PER BRANCH. A Stop hook sees no PR body, so it cannot tell a punt
# from a row this branch is landing a fix for; repeating the pointer every turn is
# how the channel stops being read. `land` is unaffected — the gate there reads the
# body and does not consult this record.
@test "the punt pointer fires once and then goes quiet for that row" {
	repo=$(punt_repo)
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[[ "$output" == *"filed-over-own-diff"* ]]
	run stop 'Landed on main by fast-forward, CI green.'
	[ "$status" -eq 0 ]
	# The PUNT pointer is spent. The row may still be named by the fifth rule's
	# checklist, which asks a different question about the same id and is
	# suppressed on its own set — so the assertion is about this rule's marker,
	# not about the id ever appearing again.
	[[ "$output" != *"filed-over-own-diff"* ]]
}

@test "a second row still gets its own pointer after the first is spent" {
	repo=$(punt_repo)
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[[ "$output" == *"CLOUD-900"* ]]
	printf 'issue CLOUD-901 2026-08-19T00:00:00.000Z ready 1 a/one.rs\n' \
		>>"$repo/.git/batten-receipts/board-writes.work"
	run stop 'Landed on main by fast-forward, CI green.'
	[[ "$output" == *"CLOUD-901"* ]]
	[[ "$output" != *"CLOUD-900"* ]]
}

# --- the fourth rule: work not landed (CLOUD-97) ------------------------------
#
# The first rule here that reports repository state rather than inferring from
# prose. It decides nothing itself, so these drive it through the same stub seam
# `tests/unlanded-check.bats` uses: what is under test is stop-guard's ORDERING
# and framing of the verdict, not the verdict.

# `unlanded_stub <count>` — a fake `batten` whose `state list` reports an
# unlanded finding on the branch of the repo under test.
unlanded_stub() {
	local repo="$1" count="$2"
	local bin="$BATS_TEST_TMPDIR/batten-stub"
	local branch
	branch=$(git -C "$repo" symbolic-ref --quiet --short HEAD)
	# IT DELEGATES EVERYTHING ELSE TO THE REAL BINARY, which is not optional:
	# `payload-field` resolves `BATTEN_BIN` too, so a stub that answers only
	# `state list` silently empties the payload every rule above reads — and the
	# suite then measures the reader being broken rather than the rule being
	# ordered. Cost one debugging round; stated here so it costs nobody another.
	local real="$BATS_TEST_DIRNAME/../target/release/batten"
	[ -x "$real" ] || real="$BATS_TEST_DIRNAME/../target/debug/batten"
	{
		echo '#!/usr/bin/env bash'
		echo 'if [ "$1" = "state" ] && [ "$2" = "list" ]; then'
		printf '\techo "abc123 completion.unlanded refs/heads/%s %s"\n' "$branch" "$count"
		echo '	exit 0'
		echo 'fi'
		printf 'exec %s "$@"\n' "$real"
	} >"$bin"
	chmod +x "$bin"
	printf '%s' "$bin"
}

# A repo with a commit its landing target does not have, plus no filed rows.
plain_repo() {
	local repo="$BATS_TEST_TMPDIR/plain"
	rm -rf "$repo"
	mkdir -p "$repo"
	git -C "$repo" init --quiet --initial-branch=work
	git -C "$repo" config user.email t@example.com
	git -C "$repo" config user.name t
	printf 'x\n' >"$repo/a.txt"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m base
	printf '%s' "$repo"
}

@test "UNLANDED WORK AT A DECLARED STOPPING POINT IS POINTED AT" {
	local repo bin
	repo=$(plain_repo)
	bin=$(unlanded_stub "$repo" 2)
	run env -u BATTEN_UNLANDED_CHECK_BYPASS \
		CLAUDE_PROJECT_DIR="$repo" BATTEN_BIN="$bin" \
		bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Pushed.\"}' | $GUARD"
	kicked "$output"
	[[ "$output" == *"unlanded: 2 commit(s)"* ]]
	[[ "$output" == *"Land it, or say what blocks it"* ]]
	[ "$status" -eq 0 ]
}

@test "the unlanded pointer carries no transcript text and no store key" {
	# Pointer, never payload: the verdict was derived from a session transcript,
	# which is the largest piece of prose anywhere near this hook.
	local repo bin
	repo=$(plain_repo)
	bin=$(unlanded_stub "$repo" 1)
	run env -u BATTEN_UNLANDED_CHECK_BYPASS \
		CLAUDE_PROJECT_DIR="$repo" BATTEN_BIN="$bin" \
		bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Pushed.\"}' | $GUARD"
	[[ "$output" != *"abc123"* ]]
	[[ "$output" != *"refs/heads"* ]]
}

@test "the unlanded rule yields to the measured posture rule" {
	# Precedence is earned, not asserted: `hedged-flag-framing` has 3/3 measured
	# precision and this rule has no measurement yet, so a turn that earns both
	# gets the measured one.
	local repo bin
	repo=$(plain_repo)
	bin=$(unlanded_stub "$repo" 1)
	run env -u BATTEN_UNLANDED_CHECK_BYPASS \
		CLAUDE_PROJECT_DIR="$repo" BATTEN_BIN="$bin" \
		bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Worth noting the receipt is stale.\"}' | $GUARD"
	[[ "$output" == *"hedged-flag-framing"* ]]
	[[ "$output" != *"unlanded:"* ]]
}

@test "landed work falls through to the closing question" {
	local repo bin
	repo=$(plain_repo)
	bin=$(unlanded_stub "$repo" 0)
	run env -u BATTEN_UNLANDED_CHECK_BYPASS \
		CLAUDE_PROJECT_DIR="$repo" BATTEN_BIN="$bin" \
		bash -c "jq -nc '{stop_hook_active:false,last_assistant_message:\"Landed.\"}' | $GUARD"
	[[ "$output" == *'"additionalContext":"done?"'* ]]
}

# --- the fifth rule: the rows this branch spun off ----------------------------

@test "EVERY ROW THE BRANCH FILED IS ENUMERATED FOR RE-EVALUATION" {
	# Rule 3 asks which filed row names a file this branch has open — a measured,
	# narrow predicate. This asks the broad question no predicate scores: for each
	# row, by number, is it really independent work? So the assertion is that ALL
	# of them are listed, including the ones rule 3 would never mention.
	local repo="$BATS_TEST_TMPDIR/filed"
	rm -rf "$repo"
	mkdir -p "$repo/a"
	git -C "$repo" init --quiet --initial-branch=work
	git -C "$repo" config user.email t@example.com
	git -C "$repo" config user.name t
	printf 'x\n' >"$repo/a/one.rs"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m base
	git -C "$repo" update-ref refs/remotes/origin/main HEAD
	mkdir -p "$repo/.git/batten-receipts"
	{
		printf 'issue CLOUD-901 2026-08-19T00:00:00.000Z ready 0\n'
		printf 'issue CLOUD-902 2026-08-19T00:00:00.000Z ready 0\n'
	} >"$repo/.git/batten-receipts/board-writes.work"
	run env -u BATTEN_FILED_HERE_BYPASS \
		CLAUDE_PROJECT_DIR="$repo" \
		bash -c "cd $repo && jq -nc '{stop_hook_active:false,last_assistant_message:\"Filed two.\"}' | $GUARD"
	[[ "$output" == *"CLOUD-901"* ]]
	[[ "$output" == *"CLOUD-902"* ]]
	[[ "$output" == *"punt you could close here"* ]]
}

@test "the checklist repeats only when the set changes" {
	# Suppressed on the SET, not per row: a checklist with rows hidden is not a
	# checklist, and an unsuppressed one reprints itself every turn until nobody
	# reads it. Filing another row asks the whole list again.
	local repo="$BATS_TEST_TMPDIR/filed-set"
	rm -rf "$repo"
	mkdir -p "$repo/a"
	git -C "$repo" init --quiet --initial-branch=work
	git -C "$repo" config user.email t@example.com
	git -C "$repo" config user.name t
	printf 'x\n' >"$repo/a/one.rs"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m base
	git -C "$repo" update-ref refs/remotes/origin/main HEAD
	mkdir -p "$repo/.git/batten-receipts"
	local record="$repo/.git/batten-receipts/board-writes.work"
	printf 'issue CLOUD-901 2026-08-19T00:00:00.000Z ready 0\n' >"$record"

	local invoke="cd $repo && jq -nc '{stop_hook_active:false,last_assistant_message:\"ok\"}' | $GUARD"
	run env -u BATTEN_FILED_HERE_BYPASS CLAUDE_PROJECT_DIR="$repo" bash -c "$invoke"
	[[ "$output" == *"CLOUD-901"* ]]

	run env -u BATTEN_FILED_HERE_BYPASS CLAUDE_PROJECT_DIR="$repo" bash -c "$invoke"
	[[ "$output" == *'"additionalContext":"done?"'* ]]

	printf 'issue CLOUD-902 2026-08-19T00:00:00.000Z ready 0\n' >>"$record"
	run env -u BATTEN_FILED_HERE_BYPASS CLAUDE_PROJECT_DIR="$repo" bash -c "$invoke"
	[[ "$output" == *"CLOUD-901"* ]]
	[[ "$output" == *"CLOUD-902"* ]]
}
