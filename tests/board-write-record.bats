#!/usr/bin/env bats
# CLOUD-514 phase 1. The recorder that answers "what did this branch put on the
# board, and was a new row refined when it was filed".
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the record is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would write records for a real session.

setup() {
	REC="$BATS_TEST_DIRNAME/../mise-tasks/board-write-record"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# Per fixture, never inherited — a CI runner carries no global identity, so a
	# bare `git commit` here is `fatal: empty ident name` and fails only there.
	# Measured on CLOUD-513, which cost a full CI run; that gate is filed and
	# unfixed, so this stays hand-written in every fixture suite.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
}

record() {
	local branch
	branch=$(git symbolic-ref --quiet --short HEAD)
	printf '%s\n' "$(git rev-parse --git-dir)/batten-receipts/board-writes.${branch//\//-}"
}

# A Ready block that satisfies `ready-lint`'s checkable clauses. Kept minimal on
# purpose: this suite is about the recorder, and the lint has its own.
ready_body() {
	cat <<'BODY'
**Why**

A thing is broken.

**Refinement — Ready**

* **Source of truth (§1).** A file.
* **Mechanism as a computable predicate (§2).** A grep with an exit code.
* **Effect (§3).** `read`.
* **Output & exit contract (§5).** Pointer-only.
* **Commit / bump (§6).** `fix(thing)` — patch until `0.1.0`.
* **Test obligation (§7).** A bats row, shown able to fail.
* **Blockers (§8).** None.
BODY
}

# The payload goes through a FILE, and the helper prints its path. Embedding JSON
# into a `bash -c` string lets the shell reinterpret its braces and quotes before
# the body ever sees it.
#
# `tool_response` is the CONTENT-BLOCK envelope an MCP tool actually returns, not
# the flat object the docs illustrate with a Write. That distinction is the whole
# reason this suite exists.
#
# `blockers` is a SPACE-SEPARATED list, not JSON: the helper is called inside a
# `bash -c` string, so a bracketed literal arrives with its quoting mangled and
# `--argjson` rejects it. jq builds the array instead.
event() {
	local tool="${1:-mcp__Linear__save_issue}" body="${2:-}" blockers="${3:-}" input_id="${4:-}"
	[ -n "$body" ] || body=$(ready_body)
	jq -nc \
		--arg t "$tool" --arg b "$body" --arg iid "$input_id" --arg blockers "$blockers" '
		{
		  tool_name: $t,
		  tool_input: ({title: "a finding",
		                blockedBy: ($blockers | split(" ") | map(select(length > 0)))}
		               + (if $iid == "" then {} else {id: $iid} end)),
		  tool_response: [{type: "text", text: ({
		      id: "CLOUD-999", title: "a finding",
		      description: $b, updatedAt: "2026-08-13T00:00:00.000Z"
		    } | tojson)}]
		}' >"$BATS_TEST_TMPDIR/event.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/event.json"
}

# --- what gets recorded --------------------------------------------------------

@test "a created row is recorded with its id, updatedAt and a green verdict" {
	run bash -c "'$REC' < $(event)"
	[ "$status" -eq 0 ]
	[ -f "$(record)" ]
	run cat "$(record)"
	[[ "$output" == "issue CLOUD-999 2026-08-13T00:00:00.000Z ready" ]]
}

# THE ROW THIS DESIGN TURNS ON. `ready-lint`'s §8 rule cross-checks prose claiming
# a blocker against the payload's relations, and the create RESPONSE carries no
# relations at all. Linting the response alone therefore reports
# blocker-cited-without-relation on exactly the rows refined most carefully. The
# create call's own `blockedBy` argument is the whole relation set on a create, so
# it is what the synthesis uses.
@test "a row whose §8 claims a blocker still records a green verdict" {
	local body
	body=$(ready_body | sed 's/\*\*Blockers (§8).\*\* None./**Blockers (§8).** `blockedBy` CLOUD-1./')
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$body" CLOUD-1)"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" ready" ]]
}

@test "an unrefined row records a verdict of unready rather than being refused" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Just a sentence, no Ready block.')"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	run cat "$(record)"
	[[ "$output" == *" unready" ]]
}

# An update is not a board write this branch is answerable for. Recording it
# would inflate the very count the gate gets specified against.
@test "updating an existing row is never recorded" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-1)"
	[ "$status" -eq 0 ]
	[ ! -f "$(record)" ]
}

# Sink 2: recorded so the create-versus-comment ratio is observable, never judged.
@test "a comment is recorded as a comment and carries no verdict" {
	run bash -c "'$REC' < $(event mcp__Linear__save_comment)"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == "comment CLOUD-999 2026-08-13T00:00:00.000Z -" ]]
}

# CLOUD-178 measured the same connector under three names depending on the
# registration episode; a rule naming one matches none of the others, silently.
@test "all three live connector spellings are recorded identically" {
	local tool
	for tool in mcp__Linear__save_issue mcp__claude_ai_Linear__save_issue mcp__4db58e41-0000-0000-0000-000000000000__save_issue; do
		rm -f "$(record)"
		run bash -c "'$REC' < $(event "$tool")"
		[ "$status" -eq 0 ]
		run cat "$(record)"
		[[ "$output" == "issue CLOUD-999"* ]]
	done
}

@test "a tool that does not write to the board is never recorded" {
	local tool
	for tool in mcp__Linear__list_issues Bash Write mcp__serena__write_memory; do
		run bash -c "'$REC' < $(event "$tool")"
		[ "$status" -eq 0 ]
		[ ! -f "$(record)" ]
	done
}

# --- pointer-only, and failing open -------------------------------------------

# Not decorative: the text this reads is the entire issue body. Four fields reach
# the file and nothing is ever printed (non-negotiable 4).
@test "POINTER, NEVER PAYLOAD: no byte of the description reaches the record" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'SECRETMARKER in the body')"
	[ -z "$output" ]
	run cat "$(record)"
	[[ "$output" != *"SECRETMARKER"* ]]
	[ "$(wc -l <"$(record)")" -eq 1 ]
}

@test "FAIL OPEN: an unreadable, nameless or resultless payload records nothing and says nothing" {
	local payload
	for payload in 'not json' '{}' '{"tool_name":""}' '' '{"tool_name":"mcp__Linear__save_issue"}'; do
		run bash -c "printf '%s' $(printf '%q' "$payload") | '$REC'"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
		[ ! -f "$(record)" ]
	done
}

# The flat shape the docs illustrate with a Write. A body written against it would
# silently record nothing, which is why the envelope was measured.
@test "FAIL OPEN: a flat tool_response is not the MCP envelope and records nothing" {
	run bash -c "jq -nc '{tool_name:\"mcp__Linear__save_issue\",tool_input:{title:\"x\"},tool_response:{id:\"CLOUD-9\"}}' | '$REC'"
	[ "$status" -eq 0 ]
	[ ! -f "$(record)" ]
}

@test "FAIL OPEN: a detached HEAD has no branch to key a record to" {
	git checkout -q --detach
	run bash -c "'$REC' < $(event)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "FAIL OPEN: outside a git repository nothing is recorded and nothing is blocked" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run bash -c "env GIT_CEILING_DIRECTORIES='$BATS_TEST_TMPDIR' '$REC' < $(event)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass is honoured" {
	run bash -c "BATTEN_BOARD_WRITE_BYPASS=1 '$REC' < $(event)"
	[ "$status" -eq 0 ]
	[ ! -f "$(record)" ]
}

# --- the wiring ----------------------------------------------------------------

# A body no matcher reaches is inert, and the miss is silent. Suffix-anchored for
# CLOUD-178's reason, asserted here because this file cannot enforce it.
@test "the settings entry is wired, on a suffix-anchored PostToolUse matcher" {
	local settings="$BATS_TEST_DIRNAME/../.claude/settings.json"
	run jq -r '[.hooks.PostToolUse[] | select(.hooks[].command | test("board-write-record")) | .matcher] | first' "$settings"
	[ "$status" -eq 0 ]
	[[ "$output" == *"save_issue"* ]]
	[[ "$output" == *"save_comment"* ]]
	[[ "$output" != "mcp__Linear__"* ]]
}
