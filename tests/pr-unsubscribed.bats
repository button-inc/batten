#!/usr/bin/env bats
# CLOUD-518's mechanism: the webhook subscription the harness arms on every PR
# this repo opens, which AGENTS.md forbids babysitting and nothing enforced.
#
# The gate is `claim-check`'s inversion, so these rows are about the two halves
# that inversion needs to hold: `record` must bind the evidence to ONE pull
# request in ONE session, and `check` must refuse when nothing was recorded —
# while staying open where there is no session to have a subscription at all.
#
# What no row here asserts, deliberately: that GitHub's subscription state is
# empty. The gate cannot observe that (CLOUD-673 — a task is answered 401 by the
# session's own MCP endpoint), and the first cut of this change shipped a POST
# that pretended otherwise, staying green against a stubbed `curl` while removing
# exactly zero subscriptions. A suite that proves shape must not be read as
# proving effect, so this one is scoped to what it really decides.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/pr-unsubscribed"
	# A throwaway repository, so a receipt can never land in the real `.git`.
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init -q
	# Where the injected client config is looked for. Empty by default, which is
	# the off-harness reading: no session, no subscription, nothing to drop.
	CFG="$BATS_TEST_TMPDIR/cfg"
	mkdir -p "$CFG"
	export BATTEN_MCP_CONFIG_DIR="$CFG"
}

# A session exists here. Only its NAME matters to the gate — presence answers the
# one question that needs no credential — so the fixture carries nothing else.
in_session() { printf '{}' >"$CFG/mcp-config-${1:-cse_fixture}.json"; }

# What `unsubscribe_pr_activity` actually answered, observed on #490.
answer_for() { printf 'No active subscription found for owner/repo#%s on this session.' "$1"; }

gate() { (cd "$REPO" && "$GATE" "$@"); }
record() { (cd "$REPO" && "$GATE" record "$1"); }
receipts() { ls "$REPO/.git/batten-receipts" 2>/dev/null || true; }

@test "CLOUD-518: a clone with no session has nothing to drop, and check passes" {
	# The off-harness reading, and the reason this gate is safe on the landing
	# critical path: a local clone or a CI runner never had a subscription, so a
	# missing receipt is not a missing action. A gate that cannot look must never
	# become a gate that blocks everything.
	run gate check 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"no session"* ]]
	# And it does NOT claim a drop happened, which is a different fact.
	[[ "$output" != *"has dropped"* ]]
}

@test "CLOUD-518: a PR this session never unsubscribed is refused" {
	in_session
	run gate check 490
	[ "$status" -eq 1 ]
	[[ "$output" == *"no unsubscribe receipt"* ]]
	# The refusal names the command that fixes it, so the operator needs nothing
	# else — the gate's own words are what reach a stopped landing (CLOUD-407).
	[[ "$output" == *"unsubscribe_pr_activity"* ]]
	[[ "$output" == *"pr-unsubscribed record 490"* ]]
}

@test "CLOUD-518: the recorded drop is what makes check pass" {
	in_session
	run bash -c "$(declare -f answer_for); answer_for 490 | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"recorded the drop of #490"* ]]
	run gate check 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"has dropped its webhook subscription"* ]]
}

@test "CLOUD-518: an answer that does not name this PR is refused" {
	# The honest error this exists to catch: the harness pins a session to one
	# branch name for a whole engagement, so the answer from the PREVIOUS pull
	# request on that name is exactly what a hurried agent pastes.
	in_session
	run bash -c "$(declare -f answer_for); answer_for 489 | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not name #490"* ]]
	# Nothing was minted, so the landing stays refused.
	[ -z "$(receipts)" ]
	run gate check 490
	[ "$status" -eq 1 ]
}

@test "CLOUD-518: a receipt for another PR does not satisfy this one" {
	in_session
	run bash -c "$(declare -f answer_for); answer_for 489 | (cd '$REPO' && '$GATE' record 489)"
	[ "$status" -eq 0 ]
	run gate check 490
	[ "$status" -eq 1 ]
	run gate check 489
	[ "$status" -eq 0 ]
}

@test "CLOUD-518: a receipt from another SESSION does not satisfy this one" {
	# A subscription belongs to a (session, PR) pair — the harness arms one per PR
	# and delivers it to one session — so a receipt left in a clone by an earlier
	# container attests to nothing about this one.
	in_session cse_first
	run bash -c "$(declare -f answer_for); answer_for 490 | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 0 ]
	run gate check 490
	[ "$status" -eq 0 ]
	rm -f "$CFG"/mcp-config-cse_first.json
	in_session cse_second
	run gate check 490
	[ "$status" -eq 1 ]
}

@test "CLOUD-518: an empty answer is could-not-look, never a refusal" {
	# Exit 2 and exit 1 answer different questions, and a caller piping nothing
	# must not look like a session that skipped the step.
	in_session
	run bash -c ": | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
	[ -z "$(receipts)" ]
}

@test "CLOUD-518: recording off-harness mints nothing and says so" {
	run bash -c "$(declare -f answer_for); answer_for 490 | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no session"* ]]
	[ -z "$(receipts)" ]
}

@test "CLOUD-518: POINTER, NEVER PAYLOAD — no answer text is printed or stored" {
	# Non-negotiable rule 4, and here it is not a formality: the thing being
	# recorded is a message about a webhook stream, and reprinting it would emit
	# the very payload the stream is being cut to stop.
	in_session
	run bash -c "printf 'No active subscription found for owner/repo#490 SECRETMARKER' | (cd '$REPO' && '$GATE' record 490)"
	[ "$status" -eq 0 ]
	[[ "$output" != *SECRETMARKER* ]]
	run cat "$REPO/.git/batten-receipts/pr-unsubscribed.cse_fixture.490"
	[[ "$output" != *SECRETMARKER* ]]
	# What it does carry is a pointer: the PR, the session and a digest.
	[[ "$output" == *"pr 490"* ]]
	[[ "$output" == *"answer-sha256"* ]]
}

@test "CLOUD-518: a bad verb or a non-numeric PR is could-not-look" {
	run gate frobnicate 490
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage"* ]]
	run gate check "not-a-number"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not a pull request number"* ]]
}
