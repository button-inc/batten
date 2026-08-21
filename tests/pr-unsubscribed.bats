#!/usr/bin/env bats
# subject: mise-tasks/pr-unsubscribed
# CLOUD-518's mechanism: the webhook subscription the harness arms on every PR
# this repo opens, which AGENTS.md forbids babysitting and nothing enforced.
#
# The gate is `claim-check`'s inversion, so these rows are about the two halves
# that inversion needs to hold: `record` must bind the evidence to ONE pull
# request in ONE session, and `check` must refuse when nothing was recorded —
# while staying open where there is no session to have a subscription at all.
#
# CLOUD-790 added the third half: `drop`, which makes the call itself over the
# session-ingress-authenticated `/github/mcp` route. Its rows are about the one
# property that keeps an actor safe in front of a gate — it must FAIL OPEN on
# everything it cannot establish, and it must mint a receipt ONLY for a call the
# endpoint accepted.
#
# What no row here asserts, deliberately: that GitHub's subscription state is
# empty. A stubbed `curl` cannot observe that, and the first cut of CLOUD-518's
# mechanism shipped a POST that pretended otherwise, staying green against a stub
# while removing exactly zero subscriptions. A suite that proves shape must not be
# read as proving effect, so this one is scoped to what it really decides; the
# single end-to-end observation lives on CLOUD-790 as a measurement, because no
# suite can hold a per-session credential.

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

# --- the `drop` fixture (CLOUD-790) ------------------------------------------
#
# A stub `curl` ahead of the real one on PATH, plus a throwaway token file and an
# origin remote. Nothing here reaches a network, and the stub is deliberately dumb:
# it honours `-o <file>` and prints the status `-w '%{http_code}'` asked for, which
# is the whole of the contract `drop` depends on.
#
# THE STUB IS WHY THESE ROWS PROVE SHAPE AND NOT EFFECT — see the header. They are
# the right rows anyway, because every failure mode that can wedge a landing is a
# shape: minting on a status that was not 200, or exiting non-zero at all.
with_endpoint() { # with_endpoint <http-code> [body]
	BIN="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$BIN"
	printf '%s\n' \
		'#!/usr/bin/env bash' \
		'out=""; prev=""' \
		'for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done' \
		'cat >/dev/null 2>&1 || true' \
		"[ -n \"\$out\" ] && printf '%s' \"\$(cat '$BATS_TEST_TMPDIR/body')\" >\"\$out\"" \
		"printf '%s' '$1'" \
		'exit 0' >"$BIN/curl"
	chmod +x "$BIN/curl"
	printf '%s' "${2-}" >"$BATS_TEST_TMPDIR/body"
	PATH="$BIN:$PATH"
}

with_token() {
	printf 'not-a-real-token\n' >"$BATS_TEST_TMPDIR/token"
	export CLAUDE_SESSION_INGRESS_TOKEN_FILE="$BATS_TEST_TMPDIR/token"
}

with_origin() { git -C "$REPO" remote add origin https://github.com/button-inc/batten.git; }

drop() { (cd "$REPO" && PATH="$PATH" "$GATE" drop "$1"); }

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

# --- CLOUD-790: the actor -----------------------------------------------------

@test "CLOUD-790: an accepted call mints the receipt check demands, with no human in it" {
	# The whole point. No tool call, no approval prompt, no `record` — the landing
	# drops its own subscription and `check` is satisfied by what the endpoint
	# answered.
	in_session
	with_token
	with_origin
	with_endpoint 200 '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Unsubscribed"}]}}'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"recorded the drop of #490"* ]]
	# The receipt says WHICH path minted it, so a human debugging a landing can
	# tell an endpoint drop from a pasted one.
	[[ "$output" == *"via endpoint"* ]]
	run gate check 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"has dropped its webhook subscription"* ]]
}

@test "CLOUD-790: a refused call mints NOTHING, and the gate still refuses" {
	# The honest limit, as an exit code: a receipt attests to an ACCEPTED call.
	# Minting on any status would make `check` a rubber stamp for having tried.
	in_session
	with_token
	with_origin
	with_endpoint 403 'MCP server not allowed'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"http 403"* ]]
	[ -z "$(receipts)" ]
	run gate check 490
	[ "$status" -eq 1 ]
}

@test "CLOUD-790: a 200 carrying an MCP error is not an accepted call" {
	# JSON-RPC over MCP reports a tool-level refusal INSIDE a 200, so the status
	# alone is not the verdict — a tool that refused must not mint a receipt
	# saying it complied.
	in_session
	with_token
	with_origin
	with_endpoint 200 '{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[]}}'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"reported an error"* ]]
	[ -z "$(receipts)" ]
}

@test "CLOUD-790: drop NEVER blocks — every path it cannot establish exits 0" {
	# `land` runs this on every lap, ahead of the gate it feeds. An actor that
	# could refuse would be a second way to wedge a landing, in front of the one
	# that already fails open by design.
	in_session
	with_origin

	# No token file.
	CLAUDE_SESSION_INGRESS_TOKEN_FILE="" run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"no session-ingress token file"* ]]

	# A token, but the endpoint is unreachable and `curl` says so.
	with_token
	with_endpoint 000 ''
	run drop 490
	[ "$status" -eq 0 ]

	[ -z "$(receipts)" ]
}

@test "CLOUD-790: off harness there is no session, so there is nothing to drop" {
	with_token
	with_origin
	with_endpoint 200 'unsubscribed'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"no session"* ]]
	# And it never reached the endpoint, so nothing was minted from a stub.
	[ -z "$(receipts)" ]
}

@test "CLOUD-790: a clone with no origin is not a repo to guess an owner for" {
	in_session
	with_token
	with_endpoint 200 'unsubscribed'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" == *"origin"* ]]
	[ -z "$(receipts)" ]
}

@test "CLOUD-790: POINTER, NEVER PAYLOAD — the response body is neither printed nor stored" {
	# Same rule 4 obligation as `record`, and the same reasoning: the body is a
	# message about a webhook stream. It is also the one place a token could leak
	# back through an echoing endpoint, which is why this row reads the receipt.
	in_session
	with_token
	with_origin
	with_endpoint 200 '{"result":{"content":[{"type":"text","text":"SECRETMARKER"}]}}'
	run drop 490
	[ "$status" -eq 0 ]
	[[ "$output" != *SECRETMARKER* ]]
	run cat "$REPO/.git/batten-receipts/pr-unsubscribed.cse_fixture.490"
	[[ "$output" != *SECRETMARKER* ]]
	[[ "$output" == *"pr 490"* ]]
	[[ "$output" == *"answer-sha256"* ]]
}
