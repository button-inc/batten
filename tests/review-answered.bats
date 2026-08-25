#!/usr/bin/env bats
# subject: policy/review-answered.rego
#
# The second test tier for the read-the-review gate (CLOUD-859), and the one that
# is not optional. The module's own `test_` rules pin the predicate; they cannot
# prove the ENGINE builds the input it reads, because a `with input as` case
# fabricates the very shape the engine may be unable to produce — the defect class
# `.claude/rules/policy-modules.md` records twice, both instances found by adding
# this tier rather than by reading.
#
# So every case here goes through TWO real hook calls in the order a session makes
# them: a `PostToolUse` envelope carrying the declared command and a buffer, which
# is what mints the record, and then a `PreToolUse` `gh pr ready`, which is what
# reads it. Nothing writes a receipt by hand. That is what makes this the tier
# that would have caught `record_agent_fact` calling `rows_in` where the row
# declared `json-array` — a live instance, in the same change.
#
# The fixture declares the REAL command string, byte for byte from `batten.toml`,
# so a rewording of it there fails here rather than silently ending the coupling.
# The engine never executes it — it compares `envelope.command` to the
# declaration and counts `envelope.result` — which is exactly what lets these
# cases cover shapes a live `gh` call could not be made to produce on demand.

setup() {
	load helpers

	# The same resolution chain `tests/run-shape.bats` uses, and for its measured
	# reason: there is no release build when `test:bats` runs in CI, and a shorter
	# chain took every case with it.
	BIN=""
	for candidate in \
		"${BATTEN_BIN:-}" \
		"$BATS_TEST_DIRNAME/../target/release/batten" \
		"$BATS_TEST_DIRNAME/../target/debug/batten"; do
		[ -n "$candidate" ] && [ -x "$candidate" ] || continue
		BIN="$candidate"
		break
	done
	[ -n "$BIN" ] || BIN="$(command -v batten || true)"
	[ -n "$BIN" ] || skip "no batten binary to drive"

	MODULE="$BATS_TEST_DIRNAME/../policy/review-answered.rego"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/policy"
	cp "$MODULE" "$REPO/policy/review-answered.rego"

	# THE DECLARED COMMAND, read out of this repository's own `batten.toml` rather
	# than retyped. Byte-equality is the forgery control, so a copy here that
	# drifted would leave every case passing over a string the real gate does not
	# use — the coupling this suite exists to hold.
	#
	# ONE READER, not two. The first draft tried `batten config show --json` and
	# fell back to a text read; the fallback had to cover the same ground anyway,
	# so the first stage was a second way to get the same string and therefore a
	# second way to get it wrong. It reads the row BY NAME rather than taking the
	# first `[[fact]]` block, so adding a second fact row above this one cannot
	# silently repoint every case in this file at the wrong command.
	DECLARED=$(
		python3 - "$BATS_TEST_DIRNAME/../batten.toml" review-answered <<'READER'
import re, sys

text, want = open(sys.argv[1]).read(), sys.argv[2]
for block in text.split("[[fact]]")[1:]:
    name = re.search(r'^name = "(.*)"$', block, re.M)
    command = re.search(r'^command = "(.*)"$', block, re.M)
    if name and command and name.group(1) == want:
        print(command.group(1))
        break
READER
	)
	[ -n "$DECLARED" ] || skip "no [[fact]] row named review-answered in batten.toml"

	{
		echo "version = 1"
		echo
		echo "[[fact]]"
		echo 'name = "review-answered"'
		echo 'returns = "json-array"'
		printf 'command = "%s"\n' "$DECLARED"
		echo
		echo "[[rule]]"
		echo 'id = "ready-needs-an-answered-review"'
		echo 'kind = "receipt"'
		echo 'scope = "mediated_call"'
		echo 'severity = "deny"'
		echo 'pattern = "gh pr ready"'
		echo 'checks = ["review-answered"]'
		echo 'key = "head"'
		echo 'reason = "run the declared command"'
		echo
		echo "[[rule]]"
		echo 'id = "review-answered"'
		echo 'kind = "policy"'
		echo 'scope = "mediated_call"'
		echo 'module = "policy/review-answered.rego"'
		echo 'severity = "deny"'
	} >"$REPO/batten.toml"

	# No global or system config: a contributor's own git settings must not be
	# able to change a verdict here (CLOUD-282).
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"
}

# Mint the record the way a session does: a PostToolUse envelope carrying the
# declared command and the buffer the host handed back.
record() { # record <stdout-bytes>
	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PostToolUse","session_id":"sess-review","cwd":"/repo","tool_name":"Bash","tool_input":{"command":sys.argv[1]},"tool_response":{"stdout":sys.argv[2],"stderr":""}}))' "$DECLARED" "$1")
	(cd "$REPO" && printf '%s' "$envelope" | "$BIN" hook --harness claude-code)
}

# Read it: the call the gate exists to judge.
ready() { # ready [<extra args>]
	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "gh pr ready 702${1:+ $1}")
	(cd "$REPO" && printf '%s' "$envelope" | "$BIN" hook --harness claude-code)
}

# BOTH HELPERS ASSERT THE EXIT STATUS, for `tests/run-shape.bats`' measured
# reason: `batten hook` prints nothing on an allow and exits 0 either way, so a
# substring check over an empty string is true — including the empty output of a
# binary that died before it judged anything.
denied() { [ "$status" -eq 0 ] && [[ "$1" == *'"permissionDecision":"deny"'* ]]; }
allowed() { [ "$status" -eq 0 ] && [[ "$1" != *'"deny"'* ]]; }

# --- the two refusals, and which row owns each ------------------------------

@test "a ready with no record at all is refused, and the receipt row names the command" {
	# The did-you-look half. The deny is built from the DECLARED command rather
	# than from prose, which is the property that makes the remedy runnable.
	run ready
	denied "$output"
	[[ "$output" == *"gh api graphql"* ]]
	[[ "$output" == *"reviewThreads"* ]]
}

@test "THE MEASURED SHAPE: a head carrying unresolved threads is refused, naming the count" {
	# #623's four open threads, as the projection emits them: one element per
	# thread id.
	run record '["PRRT_a","PRRT_b","PRRT_c","PRRT_d"]'
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
	[[ "$output" == *"review-unanswered"* ]]
	[[ "$output" == *"4 blocking"* ]]
	# Pointer-only (non-negotiable rule 4): the ids are not in the engine, so a
	# message naming one would be a payload this channel refuses to carry.
	[[ "$output" != *"PRRT_a"* ]]
}

@test "a head whose threads are all answered is allowed" {
	# THE LOAD-BEARING HALF. A predicate that only ever denied would satisfy every
	# case above and gate nothing (CLOUD-418). `[]` is the genuine zero: the
	# command looked and found none.
	run record '[]'
	[ "$status" -eq 0 ]
	run ready
	allowed "$output"
}

# --- the vacuity cases the row enumerates -----------------------------------

@test "VACUITY: zero threads and no review reads as unreviewed, not as all-addressed" {
	# #618 carries no threads and no review. The projection emits the PR author's
	# login when nothing but the author reviewed, so the honest count is one — and
	# a thread-only predicate would have read this as zero and passed it.
	run record '["wenzowski"]'
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
	[[ "$output" == *"1 blocking"* ]]
}

@test "VACUITY: a buffer that is not the declared shape records nothing rather than one row" {
	# `returns = "json-array"` (CLOUD-993). A `gh` that printed an auth error, or a
	# wrapper that annotated its own output, must not become `rows 1` — which would
	# be a refusal nobody can clear — nor `rows 0`, which would be a pass over a
	# command that never answered. It records NOTHING, so the receipt row's
	# did-you-look refusal stands.
	run record 'gh: could not determine the current repository'
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
	[[ "$output" == *"gh api graphql"* ]]
}

@test "VACUITY: an empty buffer is not zero rows" {
	# A command that printed nothing is could-not-look, not "there are none".
	# Recording a zero here would turn silence into a pass.
	run record ''
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
}

@test "a buffer from a command nobody asked for never becomes the record" {
	# The forgery control, over this fact: the agent chooses WHICH command runs and
	# does not author what it prints, so byte-equality against the declaration is
	# what stands between the two.
	local envelope
	envelope=$(python3 -c 'import json; print(json.dumps({"hook_event_name":"PostToolUse","session_id":"s","cwd":"/repo","tool_name":"Bash","tool_input":{"command":"echo []"},"tool_response":{"stdout":"[]","stderr":""}}))')
	run bash -c "cd '$REPO' && printf '%s' '$envelope' | '$BIN' hook --harness claude-code"
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
}

# --- what must NOT be refused ----------------------------------------------

@test "a re-draft is not a ready, even on a head carrying findings" {
	# `land` re-drafts on a red run, and that is the one thing that stops the next
	# push buying another matrix (CLOUD-240). Refusing it would leave the tap open
	# on exactly the head this gate is keeping out of CI.
	run record '["PRRT_a","PRRT_b"]'
	[ "$status" -eq 0 ]
	run ready '--undo'
	allowed "$output"
}

@test "VACUITY: a page the command could not read refuses rather than passing" {
	# GitHub caps a connection page at 100, so a PR with more threads than that
	# would have the surplus fall outside the query — and an unresolved thread out
	# there would leave `rows == 0`, a FALSE GREEN in the one direction this gate
	# exists to prevent. The projection emits an extra element per truncated
	# connection, so the buffer a clear-but-truncated head produces is `[true]`
	# rather than `[]`.
	#
	# THE DISCRIMINATING PAIR is this case beside "all answered": both are a head
	# with zero unresolved threads, and only the truncated one refuses. Without the
	# `pageInfo` clauses they would be the same buffer.
	run record '[true]'
	[ "$status" -eq 0 ]
	run ready
	denied "$output"
	[[ "$output" == *"1 blocking"* ]]
}

@test "THE BYPASS: a compound command is still a ready" {
	# The case an earlier draft did not have, and the reason it did not: this module
	# anchored on `startswith`, so `cd /repo && gh pr ready 702` went unjudged. The
	# receipt row DOES select it, so an existing record satisfies the did-you-look
	# half — and with the count half silent the call was allowed carrying two
	# unresolved threads. Measured exactly that before the anchor came out.
	#
	# End to end rather than only in the module's `test_` rules, because what was
	# wrong was the interaction between two rows: the receipt row's selection and
	# this module's narrowing disagreeing about the same command.
	run record '["PRRT_a","PRRT_b"]'
	[ "$status" -eq 0 ]

	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' 'cd /repo && gh pr ready 702')
	run bash -c "cd '$REPO' && printf '%s' \"\$1\" | '$BIN' hook --harness claude-code" _ "$envelope"
	denied "$output"
	[[ "$output" == *"2 blocking"* ]]
}

@test "a commit message naming the command is prose, not a ready" {
	# THE ANCHOR'S DISCRIMINATING CASE. This repository writes `gh pr ready` down
	# constantly — in commit messages, in issue bodies, in the module itself — so a
	# `contains` over the raw command refuses its own documentation, which is the
	# hazard `run-shape.rego`'s header records for the identical predicate.
	#
	# Over the binary rather than only in the module's own `test_` rules, because
	# what is at risk is the engine handing the whole command string through: a
	# `with input as` case fabricates that string and cannot show it arrives raw.
	run record '["PRRT_a","PRRT_b"]'
	[ "$status" -eq 0 ]

	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' \
		'git commit -m "run gh pr ready once the review is answered"')
	run bash -c "cd '$REPO' && printf '%s' \"\$1\" | '$BIN' hook --harness claude-code" _ "$envelope"
	allowed "$output"
}

@test "reading the review is never refused, so the remedy is reachable" {
	# A gate whose own remedy it blocks is unsatisfiable. Both `gh pr view` and the
	# declared `gh api graphql` must pass on a head with findings recorded.
	run record '["PRRT_a"]'
	[ "$status" -eq 0 ]
	local envelope
	for c in 'gh pr view 702 --json reviewDecision' "$DECLARED"; do
		envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "$c")
		run bash -c "cd '$REPO' && printf '%s' \"\$1\" | '$BIN' hook --harness claude-code" _ "$envelope"
		allowed "$output"
	done
}
