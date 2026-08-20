#!/usr/bin/env bats
# The Stop hook body: one bounded re-prompt per turn, and fail-open everywhere
# else. CLOUD-187 is why this suite carries the wiring assertion too — a hook that
# lands mid-session is not in that session's wiring, so the suite is the only
# in-session proof that the entry exists at all.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/stop-guard"
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

@test "a clean final message is silent" {
	run stop 'Landed on main by fast-forward, CI green.'
	! kicked "$output"
	[ -z "$output" ]
	[ "$status" -eq 0 ]
}

@test "an absent last_assistant_message fails open" {
	run bash -c "jq -nc '{stop_hook_active:false}' | $GUARD"
	! kicked "$output"
	[ "$status" -eq 0 ]
}

@test "the bypass is honoured" {
	BATTEN_STOP_GUARD_BYPASS=1 run stop 'Worth noting the receipt is stale.'
	! kicked "$output"
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
	run stranded 'The wiring is missing at mise-tasks/stop-guard:55.'
	[ "$status" -eq 0 ]
	kicked "$output"
	[[ "$output" == *"turn:1"* ]]
	[[ "$output" == *"finding-without-durable-write"* ]]
}

@test "POINTER, NEVER PAYLOAD: the advisory carries no byte of the turn's prose" {
	# The design in one assertion. Returning the prose makes this a mirror, and a
	# mirror is cleared by restating — the double-write CLOUD-200 and CLOUD-248
	# exist to kill. A coordinate can only be answered by going to look.
	run stranded 'Broken at mise-tasks/land:200 and SENTINELXYZZY marks it.'
	[[ "$output" != *"SENTINELXYZZY"* ]]
	[[ "$output" != *"Broken at"* ]]
}

@test "the advisory says what to do, since a coordinate alone is not an instruction" {
	run stranded 'Broken at mise-tasks/land:200.'
	[[ "$output" == *"file it"* ]]
}

@test "the shipped rule keeps precedence when both would fire" {
	# One nudge per turn. Two is how a channel stops being read, and the enforcing
	# rule has the higher measured precision.
	run stranded 'Broken at mise-tasks/land:200.' 'Worth noting the receipt is stale.'
	[[ "$output" == *"hedged-flag-framing"* ]]
	[[ "$output" != *"finding-without-durable-write"* ]]
}

@test "a turn that strands nothing is silent" {
	run stranded 'Rebased, pushed, and the gate is green.'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an unreadable transcript is silent, not a kick" {
	# Fail open, like every other path in this guard: a missing file must not
	# manufacture an advisory.
	run stop 'Pushed and green.'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the recursion bound still holds for the second rule" {
	local t="$BATS_TEST_TMPDIR/active.jsonl"
	: >"$t"
	jq -nc '{type:"user",isSidechain:false,message:{content:"go"}}' >>"$t"
	jq -nc '{type:"assistant",isSidechain:false,message:{content:[{type:"text",text:"Broken at mise-tasks/land:200."}]}}' >>"$t"
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
assert entry[0].endswith('/mise-tasks/stop-guard'), entry
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

@test "a branch with no filed row is silent" {
	repo=$(punt_repo)
	rm "$repo/.git/batten-receipts/board-writes.work"
	cd "$repo" || return 1
	unset BATTEN_FILED_HERE_BYPASS
	run stop 'Landed on main by fast-forward, CI green.'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
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
	[[ "$output" == *"CLOUD-900"* ]]
	run stop 'Landed on main by fast-forward, CI green.'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
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
