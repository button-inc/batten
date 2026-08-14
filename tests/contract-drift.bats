#!/usr/bin/env bats
# The remind-once hook over an instruction-surface snapshot (CLOUD-187).
#
# The defect it closes is measured, not hypothetical: `issue-guard` landed
# mid-session and a live session readied a PR whose branch and commits carried no
# `CLOUD-<n>` key, because that hook was never in that session's wiring. Hooks and
# instructions are session-start snapshots, and nothing told the session it had
# drifted.
#
# Two properties carry the whole design and both are asserted as BYTES rather than
# assumed: the reminder fires exactly once per change-set (so the channel stays
# worth reading), and it is a POINTER — paths and counts, never a byte of the
# changed file. A reminder carrying the new text would be a mirror, and a mirror is
# satisfied by reading the hook's own output instead of the file.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/contract-drift"
	REPO="$BATS_TEST_TMPDIR/repo"

	# A fixture repo carrying the same surface shape the real one does, so the
	# pathspec list in the task is exercised rather than mocked.
	mkdir -p "$REPO/.claude/rules" "$REPO/mise-tasks"
	git -C "$REPO" init -q -b work
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	printf 'the contract\n' >"$REPO/AGENTS.md"
	printf 'a rule\n' >"$REPO/.claude/rules/rust.md"
	printf '{"hooks":{}}\n' >"$REPO/.claude/settings.json"
	printf 'amends "hk@1.0.0"\n' >"$REPO/hk.pkl"
	printf '#!/usr/bin/env bash\ntrue\n' >"$REPO/mise-tasks/some-gate"
	printf 'ignored/\n' >"$REPO/.gitignore"
	git -C "$REPO" add -A
	git -C "$REPO" commit -qm "seed"

	SNAPSHOTS="$REPO/$(git -C "$REPO" rev-parse --git-dir)/batten-contract"
}

# Drive it the way a hook does: the payload on stdin, from inside the repo.
drift() {
	local session="${1:-s-1}" event="${2:-PostToolBatch}"
	jq -nc --arg s "$session" --arg e "$event" \
		'{session_id: $s, hook_event_name: $e}' |
		(cd "$REPO" && "$TASK")
}

# --- the seed, and silence as the default -----------------------------------

@test "the first call is the session's start: silent, and it writes a snapshot" {
	# There is no "before" to have drifted from, so a seed is never a reminder.
	run drift
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	[ -f "$SNAPSHOTS/s-1" ]
}

@test "an unchanged surface produces no output" {
	drift
	run drift
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the snapshot is one line per tracked contract file, hash and path" {
	drift
	run bash -c "wc -l <'$SNAPSHOTS/s-1'"
	[ "$output" -eq 5 ]
	run grep -cE '^[0-9a-f]{40} [^ ]+$' "$SNAPSHOTS/s-1"
	[ "$output" -eq 5 ]
}

# --- the reminder ------------------------------------------------------------

@test "THE GAP: a modified AGENTS.md is reported, naming the file" {
	drift
	printf 'a mid-session change\n' >>"$REPO/AGENTS.md"
	run drift
	[ "$status" -eq 0 ]
	[[ "$output" == *'"additionalContext"'* ]]
	[[ "$output" == *"AGENTS.md"* ]]
}

@test "it names the event it was called on, so one body serves both wirings" {
	# Matched WITHOUT the separator, because the separator is not the property.
	# The document is emitted compactly since CLOUD-479 dropped `jq` from this
	# body — `jq -n` pretty-printed it with `": "` — and pinning the old spacing
	# would assert the formatter rather than the field. `jq -e` below still holds
	# the "it is valid JSON" half, which is the part that has to be true.
	drift s-2 SessionStart
	printf 'change\n' >>"$REPO/AGENTS.md"
	run drift s-2 SessionStart
	[[ "$output" == *'"hookEventName"'*'"SessionStart"'* ]]

	drift s-3 PostToolBatch
	printf 'more\n' >>"$REPO/AGENTS.md"
	run drift s-3 PostToolBatch
	[[ "$output" == *'"hookEventName"'*'"PostToolBatch"'* ]]
}

@test "ONCE PER CHANGE-SET: the very next call is silent" {
	# The rate limit is the overwrite, with no second state file to keep
	# consistent. A surface that stops moving goes quiet by itself.
	drift
	printf 'change\n' >>"$REPO/AGENTS.md"
	run drift
	[ -n "$output" ]
	run drift
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a SECOND change-set is reported again — quiet is not permanent" {
	drift
	printf 'first\n' >>"$REPO/AGENTS.md"
	drift
	printf 'second\n' >>"$REPO/.claude/rules/rust.md"
	run drift
	[[ "$output" == *".claude/rules/rust.md"* ]]
	# The already-reported file is not repeated: the comparison is against what
	# was last reported, not against the session's start.
	[[ "$output" != *"AGENTS.md"* ]]
}

@test "a newly tracked contract file is drift" {
	drift
	printf '#!/usr/bin/env bash\ntrue\n' >"$REPO/mise-tasks/brand-new-gate"
	git -C "$REPO" add mise-tasks/brand-new-gate
	run drift
	[[ "$output" == *"mise-tasks/brand-new-gate"* ]]
}

@test "a contract file that stopped being tracked is drift too" {
	drift
	git -C "$REPO" rm -q .claude/rules/rust.md
	run drift
	[[ "$output" == *"no longer tracked"* ]]
	[[ "$output" == *".claude/rules/rust.md"* ]]
}

@test "an untracked file under mise-tasks is not contract" {
	# Tracked files are the contract; scratch is not. Judging untracked paths
	# would fire on every working file an agent opens.
	drift
	printf 'scratch\n' >"$REPO/mise-tasks/notes-in-progress"
	run drift
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a file outside the surface does not fire it" {
	drift
	printf 'code\n' >"$REPO/README.md"
	git -C "$REPO" add README.md
	run drift
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- the snapshot is per session ---------------------------------------------

@test "each session gets its own snapshot, so a session that started AFTER the change is not nudged" {
	drift s-early
	printf 'landed on main\n' >>"$REPO/AGENTS.md"
	# A session opening now read the NEW file, so its own first call must be a
	# silent seed rather than a reminder about a change it already has.
	run drift s-late
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	# The earlier session, which read the old one, still gets told.
	run drift s-early
	[[ "$output" == *"AGENTS.md"* ]]
}

@test "a payload with no session_id still works, on a shared key" {
	# Degrading to a weaker answer beats a dead mechanism.
	run bash -c "jq -nc '{hook_event_name:\"PostToolBatch\"}' | (cd '$REPO' && '$TASK')"
	[ "$status" -eq 0 ]
	[ -f "$SNAPSHOTS/shared" ]
}

@test "a session id carrying path characters cannot escape the snapshot store" {
	run bash -c "jq -nc '{session_id:\"../../escape\",hook_event_name:\"PostToolBatch\"}' | (cd '$REPO' && '$TASK')"
	[ "$status" -eq 0 ]
	[ ! -e "$REPO/escape" ]
	[ ! -e "$BATS_TEST_TMPDIR/escape" ]
	run bash -c "ls '$SNAPSHOTS'"
	[[ "$output" != *".."* ]]
}

# --- pointer, never payload (non-negotiable rule 4) --------------------------

@test "the reminder carries no byte of the changed file's content" {
	drift
	local secret="ghp_thisIsTheSortOfThingAContractFileMustNeverEcho"
	printf '%s\n' "$secret" >>"$REPO/.claude/settings.json"
	run drift
	[ -n "$output" ]
	[[ "$output" != *"$secret"* ]]
	# Nor a diff of any kind: the only file-derived bytes are paths.
	[[ "$output" != *"+++"* ]]
	[[ "$output" != *"@@"* ]]
}

@test "it emits a count as well as the paths" {
	drift
	printf 'a\n' >>"$REPO/AGENTS.md"
	printf 'b\n' >>"$REPO/hk.pkl"
	run drift
	[[ "$output" == *"2 changed"* ]]
}

@test "when settings.json moved it says a new hook may not be loaded in this session" {
	# The one consequence an agent cannot infer from the file list. Worded as a
	# check rather than a certainty: a `PreToolUse` guard measurably did not load
	# mid-session (the CLOUD-187 measurement), while the `PostToolBatch` entry
	# added by this very change did.
	drift
	printf '{"hooks":{"PreToolUse":[]}}\n' >"$REPO/.claude/settings.json"
	run drift
	[[ "$output" == *"self-enforced"* ]]
}

# --- failure posture: fails open, always exit 0 ------------------------------

@test "unparseable input fails open" {
	# PostToolBatch spends exit 2 on stopping the agentic loop, so a non-zero
	# exit here would halt a turn over a bookkeeping failure.
	run bash -c "printf 'not json' | (cd '$REPO' && '$TASK')"
	[ "$status" -eq 0 ]
	[[ "$output" != *"additionalContext"* ]]
}

@test "empty input fails open" {
	run bash -c "printf '' | (cd '$REPO' && '$TASK')"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "outside a checkout there is no surface to judge" {
	mkdir -p "$BATS_TEST_TMPDIR/bare"
	run bash -c "jq -nc '{session_id:\"s\",hook_event_name:\"PostToolBatch\"}' | (cd '$BATS_TEST_TMPDIR/bare' && '$TASK')"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass is honoured" {
	drift
	printf 'change\n' >>"$REPO/AGENTS.md"
	run bash -c "jq -nc '{session_id:\"s-1\",hook_event_name:\"PostToolBatch\"}' | (cd '$REPO' && BATTEN_CONTRACT_DRIFT_BYPASS=1 '$TASK')"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the emitted document is the hook shape, and it parses" {
	drift
	printf 'change\n' >>"$REPO/AGENTS.md"
	run bash -c "jq -nc '{session_id:\"s-1\",hook_event_name:\"PostToolBatch\"}' | (cd '$REPO' && '$TASK') | jq -e '.hookSpecificOutput.additionalContext | length > 0'"
	[ "$status" -eq 0 ]
}
