#!/usr/bin/env bats
# subject: crates/batten/src/facts.rs
#
# The subject header is READ, not decoration: `bats-tests-not-deleted` resolves it
# to decide whether a suite's subject is still alive, and every other suite names
# exactly one bare path. This one named two and a parenthetical, and the ratchet
# refused it at this line. The other half of the subject is
# `crates/batten/src/receipt.rs`, which is said here in prose rather than in the
# header for that reason.
#
# An agent-sourced record is filed under the subject its receipt row's `key`
# names (CLOUD-859). Until this suite existed the record was keyed on the fact's
# NAME alone, so `key` was accepted at load and unread at decision: one clear
# answer authorised every later head on the branch, and the read-the-review gate
# that shipped in #705 bound once per branch rather than once per head.
#
# WHY THIS TIER AND NOT A UNIT TEST, stated because the temptation is real and
# `sourced_path` is a pure function two lines long. A unit test over it asserts
# that a filename contains a subject somebody passed in; it cannot show that the
# BOUNDARY resolves that subject and hands it to both halves. The defect was
# never in the filename — it was that nothing computed a subject at all. So every
# case here goes through the two real hook calls a session makes: a `PostToolUse`
# envelope carrying the declared command, which is what mints the record, and a
# `PreToolUse` `gh pr ready`, which is what reads it. Nothing writes a receipt by
# hand and nothing inspects a path to decide a case.
#
# THE ANTI-VACUITY TWIN IS THE POINT OF THE SUITE, not a courtesy: head-keying
# everything would satisfy the first case and break `claim` repo-wide, because a
# claim attests to a decision about an ISSUE and every commit on the branch
# continues to serve it. "a branch-keyed record survives a new commit" is the
# case that has to stay green.

setup() {
	load helpers

	# `batten_binary` rather than the release-first chain five suites carried:
	# `test:bats` builds DEBUG, so a leftover release binary shadowed it and a
	# suite reported on a build older than the code under test. This suite is
	# where that was measured — see the helper's own header.
	BIN=$(batten_binary "$BATS_TEST_DIRNAME/..") || skip "no batten binary to drive"

	# A CONSTANT string, which is what the channel requires: `Declared.command` is
	# compared byte-for-byte against what the agent ran, and that comparison is the
	# forgery control. The engine never executes it — it compares the command and
	# counts the result — so these cases can drive shapes a live `gh` could not be
	# made to produce on demand.
	COMMAND="gh pr view --json reviewThreads --jq '[.reviewThreads[] | select(.isResolved | not)]'"
	REPO="$BATS_TEST_TMPDIR/repo"
}

# Build the fixture repository with ONE `[[fact]]` and one `receipt` row keyed as
# asked. The keying is the only thing that varies between cases, which is what
# makes a difference in verdict attributable to it.
fixture() { # fixture <key> [max_age]
	rm -rf "$REPO"
	mkdir -p "$REPO"
	{
		echo "version = 1"
		echo
		echo "[[fact]]"
		echo 'name = "keyed"'
		echo 'returns = "json-array"'
		printf 'command = "%s"\n' "$COMMAND"
		echo
		echo "[[rule]]"
		echo 'id = "ready-needs-the-fact"'
		echo 'kind = "receipt"'
		echo 'scope = "mediated_call"'
		echo 'severity = "deny"'
		echo 'pattern = "gh pr ready"'
		echo 'checks = ["keyed"]'
		printf 'key = "%s"\n' "$1"
		if [ -n "${2:-}" ]; then printf 'max_age = %s\n' "$2"; fi
		echo 'reason = "run the declared command"'
	} >"$REPO/batten.toml"
	# No global or system config: a contributor's own git settings must not be able
	# to change a verdict here (CLOUD-282).
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"
	commit "the first commit"
}

commit() { # commit <subject>
	(cd "$REPO" &&
		GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
			git -c user.email=fixture@example.invalid -c user.name=fixture \
			commit -q --allow-empty -m "$1")
}

# Mint the record the way a session does: a PostToolUse envelope carrying the
# declared command and the buffer the host handed back.
record() { # record [<stdout-bytes>]
	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PostToolUse","session_id":"sess-keying","cwd":"/repo","tool_name":"Bash","tool_input":{"command":sys.argv[1]},"tool_response":{"stdout":sys.argv[2],"stderr":""}}))' "$COMMAND" "${1:-[]}")
	(cd "$REPO" && printf '%s' "$envelope" | "$BIN" hook --harness claude-code)
}

# Read it: the call the receipt row judges.
ready() {
	local envelope
	envelope=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "gh pr ready 999")
	(cd "$REPO" && printf '%s' "$envelope" | "$BIN" hook --harness claude-code)
}

# BOTH HELPERS ASSERT THE EXIT STATUS, for `tests/run-shape.bats`' measured
# reason: `batten hook` prints nothing on an allow and exits 0 either way, so a
# substring check over an empty string is true — including the empty output of a
# binary that died before it judged anything.
denied() { [ "$status" -eq 0 ] && [[ "$1" == *'"permissionDecision":"deny"'* ]]; }
allowed() { [ "$status" -eq 0 ] && [[ "$1" != *'"deny"'* ]]; }

# The record filenames in the store, one per line.
#
# A glob rather than `find -printf`: that flag is GNU-only, and macOS `find`
# rejects it — so on a Mac this would print nothing and every non-empty assertion
# below would fail on the tool rather than on the gate. That is the class
# `tests/helpers.bash` exists for (CLOUD-282), and CI cannot catch it because CI
# is ubuntu. A glob is already sorted, so nothing else is needed.
records() {
	local file names=""
	for file in "$REPO"/.git/batten-receipts/fact.*; do
		[[ -e "$file" ]] || continue
		names="${names}${names:+$'\n'}$(basename "$file")"
	done
	printf '%s\n' "$names"
}

# Backdate every record in the store by `$1` seconds.
#
# `python3` rather than `touch -d '2 hours ago'`: BSD `touch` reads `-d` as an
# ISO timestamp and rejects a relative expression outright, and these suites
# already depend on python3 for their envelopes.
age_records() { # age_records <seconds>
	python3 - "$REPO/.git/batten-receipts" "$1" <<'AGE'
import glob, os, sys, time

store, seconds = sys.argv[1], int(sys.argv[2])
when = time.time() - seconds
for path in glob.glob(os.path.join(store, "fact.*")):
    os.utime(path, (when, when))
AGE
}

# --- the defect, and the case that shows it able to fail ---------------------

@test "a head-keyed record cleared on one commit does not satisfy the check on the next" {
	# THE MEASURED DEFECT. Before this change the record filed under the fact's
	# name, so the second `ready` here was ALLOWED — an agent ran the command, got a
	# clear answer, pushed a fix nobody had reviewed, and readied it.
	fixture head
	run record '[]'
	[ "$status" -eq 0 ]
	run ready
	allowed "$output"

	commit "a fix nobody has looked at"
	run ready
	denied "$output"
	# The remedy is the DECLARED command, unchanged: a record under a new head is
	# simply missing, so no new verdict and no new message were needed.
	[[ "$output" == *"gh pr view --json reviewThreads"* ]]
}

# --- the anti-vacuity twin, which is what stops the fix being "key by head" ---

@test "ANTI-VACUITY: a branch-keyed record still satisfies the check after a new commit" {
	# The case that has to stay green. `claim-needs-receipt` is keyed by branch
	# precisely because a claim attests to a decision about an issue that every
	# commit on the branch continues to serve — CLOUD-516's incident read the other
	# way round. A fix that head-keyed every record would pass the case above and
	# make `claim` demand a re-claim per commit, which is the false-positive rate
	# that gets a guard bypassed.
	fixture branch
	run record '[]'
	[ "$status" -eq 0 ]
	commit "one more commit on the same claim"
	run ready
	allowed "$output"
}

@test "a branch-keyed record does not follow the checkout onto another branch" {
	# And the twin's own twin: `branch` must be a real subject rather than a way of
	# spelling "never expires". A record minted on one branch is absent on the next,
	# which is the same could-not-look the missing-record arm already carries.
	fixture branch
	run record '[]'
	[ "$status" -eq 0 ]
	run ready
	allowed "$output"

	(cd "$REPO" && git checkout -q -b claude/somewhere-else)
	run ready
	denied "$output"
}

# --- the key is read at all --------------------------------------------------

@test "head and branch keyings file the record under different names" {
	# The cheapest statement of "the column is load-bearing": two fixtures differing
	# only in `key` put the record in two different places. Read off the store
	# rather than asserted about a path, so this fails if the boundary stops
	# resolving a subject even though `sourced_path` still accepts one.
	fixture head
	run record '[]'
	[ "$status" -eq 0 ]
	local head_named
	head_named=$(records)
	[ -n "$head_named" ]

	fixture branch
	run record '[]'
	[ "$status" -eq 0 ]
	local branch_named
	branch_named=$(records)
	[ -n "$branch_named" ]

	[ "$head_named" != "$branch_named" ]
	# The branch-keyed one names the branch; the head-keyed one does not.
	[[ "$branch_named" == *"main"* ]]
	[[ "$head_named" != *"main"* ]]
}

# --- the clock, discarded on this path until now ------------------------------

@test "max_age bounds an agent-sourced record, and an unaged one still passes" {
	# CLOUD-988's column reached `receipt_facts` and the agent-sourced loop never
	# read it, so neither the head nor the clock bounded the evidence. Both halves
	# here, because a bound that refused everything would pass the first assertion
	# alone.
	fixture head 3600
	run record '[]'
	[ "$status" -eq 0 ]
	run ready
	allowed "$output"

	# Aged by the fixture rather than by waiting: the property under test is that
	# the bound is READ, and a suite that slept an hour would assert the same thing
	# and cost an hour.
	age_records 7200
	run ready
	denied "$output"
}

# --- what a keying nobody can file under does --------------------------------

@test "a named keying over an agent-sourced fact is refused at LOAD, not at decision" {
	# The two halves run on different envelopes: the record is written on the
	# post-tool event of the fact's own command, and a `named` subject is projected
	# out of the call the row selects. So a `named` agent-sourced check would deny
	# forever and running the command it names would not satisfy it — a gate nobody
	# can clear, which is the failure this whole row exists to end. Refused where it
	# can still be fixed rather than shipped as a column that files nothing.
	fixture head
	python3 - "$REPO/batten.toml" <<'PATCH'
import sys
path = sys.argv[1]
text = open(path).read().replace('key = "head"', 'key = "named"\nkey_from = "input-id"')
open(path, "w").write(text)
PATCH
	run ready
	# Exit 1 and a usage error, never exit 2: this is config the operator wrote
	# being refused, not a verdict about the call.
	[ "$status" -eq 1 ]
	[[ "$output" == *"key = \"named\""* ]]
	[[ "$output" == *"keyed"* ]]
}
