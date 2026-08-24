#!/usr/bin/env bats
# subject: mise-tasks/board-write-record.sh
# CLOUD-514 phase 1. The recorder that answers "what did this branch put on the
# board, and was a new row refined when it was filed".
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the record is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would write records for a real session.

setup() {
	REC="$BATS_TEST_DIRNAME/../mise-tasks/board-write-record.sh"
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

# A `save_comment` event. The response is the COMMENT object — a uuid `id`, and no
# reference to the row it landed on — which is exactly why the id must come from
# the input's parent reference instead.
#
# `target` empty with `other_parent` set models a reply (`parentId`) or a comment
# on a project/document; both carry no `issueId`.
comment_event() {
	# `${2-…}` and not `${2:-…}`: an explicitly EMPTY target is the reply case and
	# must stay empty, where `:-` would substitute the default over it.
	local tool="${1:-mcp__Linear__save_comment}" target="${2-CLOUD-42}" other_parent="${3:-}"
	jq -nc --arg t "$tool" --arg target "$target" --arg other "$other_parent" '
		{
		  tool_name: $t,
		  tool_input: ((if $target == "" then {} else {issueId: $target} end)
		               + (if $other == "" then {} else {($other): "abc-123"} end)
		               + {body: "a finding"}),
		  tool_response: [{type: "text", text: ({
		      id: "4d16245a-43ea-49ae-b67d-c2ee0b64b96e",
		      body: "a finding", updatedAt: "2026-08-13T00:00:00.000Z"
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
	[[ "$output" == "issue CLOUD-999 2026-08-13T00:00:00.000Z ready - 0 -" ]]
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
	[[ "$output" == *" ready - 0 "* ]]
}

@test "an unrefined row records a verdict of unready rather than being refused" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Just a sentence, no Ready block.')"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
	run cat "$(record)"
	[[ "$output" == *" unready - 0 "* ]]
}

# --- the diff column (CLOUD-514, phase 3) -------------------------------------
#
# The overlap is `-` everywhere above because a throwaway `git init` has no
# `origin/main` to diff against — which is the fail-open reading, and the reason
# every case that predates this column still holds. These two build the ref so
# the column can carry a real answer, in both directions.
with_diff() { # a branch whose diff against origin/main touches ONE tracked file
	printf 'x\n' >"$REPO/keeper.rs"
	printf 'y\n' >"$REPO/untouched.rs"
	git -C "$REPO" add keeper.rs untouched.rs
	git -C "$REPO" commit -q -m base
	git -C "$REPO" update-ref refs/remotes/origin/main HEAD
	git -C "$REPO" checkout -q -b work
	printf 'x2\n' >"$REPO/keeper.rs"
	git -C "$REPO" commit -q -am change
}

@test "a row whose body names a changed file records a non-zero overlap" {
	with_diff
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'The bug is in keeper.rs:12.')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 1,keeper.rs 0 "* ]]
}

# --- the §1 column (CLOUD-854) -------------------------------------------------
#
# The fifth column holds every path a body names, and that set cannot tell a row
# CLAIMING a file from one CITING it as evidence — measured five times, each
# costing an override. §1 of a Ready block names the source of truth by
# construction, so the seventh column is that clause's paths alone and
# `filed-here-check` intersects the two.
#
# These two cases are the discriminating pair: identical bodies but for WHICH
# clause names the file, and the columns must disagree.

@test "A PATH NAMED ONLY OUTSIDE §1 IS IN THE NAMED COLUMN AND NOT THE §1 ONE" {
	with_diff
	local body
	# §1 names nothing tracked; the prose cites `keeper.rs` as where the bug was
	# measured — the shape CLOUD-732 requires and this column must not punish.
	body=$(ready_body | sed 's/^\*\*Why\*\*$/**Why**\n\nMeasured in keeper.rs:12./')
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$body")"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	# The whole point of the pair: the named column HAS the cited path and the §1
	# column does NOT, so the two disagree and `filed-here-check` can tell them
	# apart. Anchored on the line end, because a suffix that stopped at the cites
	# column would pass whatever the §1 column said.
	[[ "$output" == *" 1,keeper.rs 0 0" ]]
}

@test "a path named IN §1 reaches the §1 column, so a real claim is still visible" {
	with_diff
	local body
	body=$(ready_body | sed 's/\*\*Source of truth (§1).\*\* A file./**Source of truth (§1).** `keeper.rs`./')
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$body")"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 1,keeper.rs 0 1,keeper.rs" ]]
}

# THE OTHER DIRECTION (CLOUD-418): a suite that only ever asserts the firing
# cannot tell a working sensor from one that names every file in the repository.
# Here that means a body naming NOTHING TRACKED records `0` — the column is the
# paths the row names, so an untracked mention is the only thing that can be empty.
@test "a row naming nothing tracked records a zero" {
	with_diff
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'The bug is in nosuchfile.rs:12.')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 0 0 "* ]]
	[[ "$output" != *nosuchfile.rs* ]]
}

# CLOUD-774. THE COLUMN IS WHAT THE ROW NAMES, NOT AN INTERSECTION, and this is the
# case that pins the change. A file the branch has not touched is still recorded,
# because the diff it will be judged against does not exist yet: rows are filed
# before any edit — AGENTS.md says claim before writing code — and freezing the
# intersection there recorded `0` for every one of them. `filed-here-check`
# intersects when it is asked.
@test "A FILE THIS BRANCH HAS NOT TOUCHED IS STILL RECORDED" {
	with_diff
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'The bug is in untouched.rs:12.')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 1,untouched.rs 0 "* ]]
}

# POINTER, NEVER PAYLOAD (non-negotiable 4). The recorder reads an entire issue
# body; the only thing that may reach the file from it is a tracked path.
@test "nothing from the body but a tracked path reaches the record" {
	with_diff
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'keeper.rs leaks hunter2 for acct 00219.')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *keeper.rs* ]]
	[[ "$output" != *hunter2* ]]
	[[ "$output" != *00219* ]]
}

# An update is not a board write this branch is answerable for. Recording it
# would inflate the very count the gate gets specified against.
@test "updating an existing row is never recorded" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-1)"
	[ "$status" -eq 0 ]
	[ ! -f "$(record)" ]
}

# THE ONE EXCEPTION, and `filed-here-check`'s third remedy is unreachable without
# it. That gate tells a branch which filed an unrefined row to groom it to Ready
# and re-run `land` — but a groom is a `save_issue` WITH an id, so the rule above
# skipped it and the creation-time `unready` stood forever. Measured on PR #525:
# the row was groomed until `ready-lint` exited 0 over the tracker's own response,
# and the refusal did not move. Remedies 1 and 2 cannot reach it either once a
# line exists, so the only escape left was the bypass — which that gate's own
# suite does not scrub, so exporting it turned six refusal cases green.
@test "a groom of a row THIS branch filed is recorded" {
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Just a sentence, no Ready block.')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" unready - 0 "* ]]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-999)"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$(record)")" -eq 2 ]
	run tail -1 "$(record)"
	[[ "$output" == "issue CLOUD-999 2026-08-13T00:00:00.000Z ready - 0 -" ]]
}

# --- the update path asserts nothing about relations (CLOUD-781) --------------
#
# ONE BODY, TWO PATHS, so the pair differs only in whether an `id` is present in
# the call. `save_issue` relations are APPEND-ONLY: on a create the `blockedBy`
# argument is the whole relation set, and on a groom it is a patch, so an absent
# argument means "unchanged", never "none". Synthesising `[]` from it asserted
# the row had no blockers — a claim the recorder never checked — and the §8
# clause citing a real one recorded `unready`.
#
# Measured 2026-08-20: a groom whose §8 cited a blocker recorded `unready`, and
# the identical body re-saved with `blockedBy` restated (a no-op against the
# tracker) recorded `ready`. `filed-here-check` then refused the lap of a branch
# that had done exactly what that gate's third remedy tells it to do.

# A §8 clause citing a blocker, over the suite's own Ready body.
cites_a_blocker() {
	ready_body | sed 's/\*\*Blockers (§8).\*\* None./**Blockers (§8).** `blockedBy` CLOUD-1./'
}

@test "a groom whose §8 cites a blocker is unjudgeable, not unready" {
	# THE ROW CLOUD-781 EXISTS FOR, and it is red against the recorder as it
	# shipped — the groom passes no `blockedBy`, exactly as a body-only edit does.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Just a sentence, no Ready block.')"
	[ "$status" -eq 0 ]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_a_blocker)" '' CLOUD-999)"
	[ "$status" -eq 0 ]
	run tail -1 "$(record)"
	# `-` is "could not lint", which `filed-here-check` passes by design. Never
	# `unready`, which is a verdict about a Ready block nothing could judge.
	#
	# The sixth column is `1:CLOUD-1` rather than `0` (CLOUD-923): the §8 clause
	# cites that row and the groom passed it as no relation, which is the whole of
	# what that column counts. The verdict columns are unaffected — the two read
	# different things about the same write.
	[[ "$output" == "issue CLOUD-999 2026-08-13T00:00:00.000Z - - 1:CLOUD-1 -" ]]
}

@test "A CREATE CITING A BLOCKER IT DID NOT PASS IS STILL UNREADY" {
	# THE ANTI-WEAKENING PIN. The toll that prices refinement lives on the create
	# path, where the argument really is the whole relation set — so "no edges" is
	# an answer there and the citation is a real violation. This case turns red if
	# the omission above is applied to the create path, which is the one way this
	# change could weaken the toll.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_a_blocker)")"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	# `1:CLOUD-1` in the sixth column, for CLOUD-923's reason: the §8 clause cites
	# that row and this create passed it as no relation. Independent of the verdict —
	# the same citation makes the toll fire AND the edge get counted, from the two
	# different questions the two columns ask.
	[[ "$output" == *" unready - 1:CLOUD-1 "* ]]
}

@test "a groom of a genuinely unready body still records unready" {
	# The omission gives up ONE clause, not the verdict: §1 through §7 are judged
	# from the body alone and are unaffected by what relations could not be seen.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Just a sentence, no Ready block.')"
	[ "$status" -eq 0 ]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue 'Still just a sentence, no Ready block.' '' CLOUD-999)"
	[ "$status" -eq 0 ]
	run tail -1 "$(record)"
	[[ "$output" == *" unready - 0 "* ]]
}

# The exception is narrow on purpose: it grants nothing a fresh create would not
# have granted, because the row is one this branch is already answerable for.
# Anyone else's row is skipped exactly as it was.
@test "a groom of a row this branch did NOT file is still skipped" {
	run bash -c "'$REC' < $(event)"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$(record)")" -eq 1 ]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-1)"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$(record)")" -eq 1 ]
}

# The record is matched on the whole id field, anchored both ends. An unanchored
# read would let a create of CLOUD-999 make a groom of CLOUD-9 — a different row
# entirely — look like this branch's own.
@test "an id that merely PREFIXES a filed one does not count as filed here" {
	run bash -c "'$REC' < $(event)"
	[ "$(wc -l <"$(record)")" -eq 1 ]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-9)"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$(record)")" -eq 1 ]
}

# COMMENTING ON A ROW IS NOT FILING IT. The exception is scoped to rows this
# branch CREATED, which is the set `filed-here-check` gates; letting a comment
# line qualify would open the update path on every row anyone commented on.
# --- CLOUD-923: the rows a body cites that the caller never passed -------------
#
# The tracker auto-links every `CLOUD-nnn` mention into a symmetric `relatedTo`
# edge, so writing a body modifies every row it cites — passed as no parameter,
# named as no relation, reported in no response. Measured over one session: 43
# edges added, 11 passed, 32 minted by prose, so 32 rows outside its scope silently
# modified. This column is the upper bound on that set, and it reads the body the
# TRACKER STORED so a caller cannot strip the citations out of what it sends.

# A body citing $* — the rows appear only as prose, never as an argument.
cites_rows() {
	ready_body
	printf 'Evidence: %s carry the measurement.\n' "$*"
}

@test "a write records the rows its stored body cites" {
	# §7 (a). Two of the three cited rows are passed as `blockedBy`, so only the
	# third is minted by prose — the argument set is subtracted whichever direction
	# it was passed in.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_rows CLOUD-1 CLOUD-2 CLOUD-3)" 'CLOUD-1 CLOUD-2')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 1:CLOUD-3 "* ]]
	[[ "$output" != *CLOUD-1* ]]
}

@test "a write passing exactly the rows it cites records zero" {
	# §7 (b). The honest zero, and the reason the column is not simply a citation
	# count: an author who declares the edges owes nothing here.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_rows CLOUD-1 CLOUD-2)" 'CLOUD-1 CLOUD-2')"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 0 "* ]]
}

@test "zero and could-not-look are distinguishable in the record" {
	# §7 (c). A comment carries no description this can read, so its column is `-`.
	# Reading that as "no edges added" is the collapse CLOUD-251 named, and it is the
	# direction that would make this record quieter than the truth.
	run bash -c "'$REC' < $(comment_event)"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" - "* ]]
	[[ "$output" != *" 0" ]]
}

@test "the row's own key is not counted as an edge to anywhere" {
	# A body naming itself is the ordinary shape — every correction section in this
	# repository's rows does it — and it is not a relation.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_rows CLOUD-999)")"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 0 "* ]]
	[[ "$output" != *CLOUD-999\ * ]] || true
}

@test "the keys come from ready-lint's emission, not a second scan here" {
	# CLOUD-806. This file already spawns that gate on this very body, and that gate
	# is the one program in the tree that turns a Ready block into structure. The
	# assertion is a PROPERTY ONLY THE PRODUCER HAS: it orders numerically, so
	# `CLOUD-9` precedes `CLOUD-10`. A second scan here would have emitted them in
	# whatever order its own sort produced, and a lexical sort puts `CLOUD-10` first.
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_rows CLOUD-10 CLOUD-9)")"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 2:CLOUD-9,CLOUD-10 "* ]]
}

@test "a write the producer never ran for records a dash, never a zero" {
	# The emission is the guard, not the description. A row whose response carries no
	# description still REACHES the producer — the recorder substitutes an empty
	# string — so it emits an empty set and this column is the honest `0`. That is
	# worth pinning, because it is the case a reader would expect to be `-`.
	jq -nc '{
	  tool_name: "mcp__Linear__save_issue",
	  tool_input: {title: "x", blockedBy: []},
	  tool_response: [{type: "text", text: ({id: "CLOUD-999", updatedAt: "2026-08-13T00:00:00.000Z"} | tojson)}]
	}' >"$BATS_TEST_TMPDIR/nodesc.json"
	run bash -c "'$REC' < $BATS_TEST_TMPDIR/nodesc.json"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == *" 0 "* ]]

	# `-` is for a write the producer was never run for at all, which is every
	# comment: the case above in "zero and could-not-look are distinguishable"
	# asserts that arm, and this one pins that the two really are different writes
	# rather than one shape read two ways.
	run bash -c "'$REC' < $(comment_event)"
	run tail -1 "$(record)"
	[[ "$output" == *" - "* ]]
}

@test "POINTER, NEVER PAYLOAD: the citing sentence does not reach the record" {
	# The column reads the body, which is the largest thing this hook touches. Only
	# the keys and a count may leave it (non-negotiable rule 4).
	run bash -c "'$REC' < $(event mcp__Linear__save_issue "$(cites_rows CLOUD-7)")"
	run cat "$(record)"
	[[ "$output" == *"1:CLOUD-7 "* ]]
	[[ "$output" != *"carry the measurement"* ]]
	[[ "$output" != *Evidence* ]]
}

@test "a comment on a row does not make a later update to it recordable" {
	run bash -c "'$REC' < $(comment_event mcp__Linear__save_comment CLOUD-999)"
	[ "$(wc -l <"$(record)")" -eq 1 ]

	run bash -c "'$REC' < $(event mcp__Linear__save_issue '' '' CLOUD-999)"
	[ "$status" -eq 0 ]
	[ "$(wc -l <"$(record)")" -eq 1 ]
}

# Sink 2: recorded so the create-versus-comment ratio is observable, never judged.
#
# THE ID IS THE ISSUE KEY, FROM THE INPUT. A `save_comment` response is the
# comment object — its `.id` is the comment's own uuid and it names no row at all
# — so reading the response here fills an issue-key column with uuids. Measured
# on this recorder's first five live rows, which did exactly that.
@test "a comment records the issue key its input names, not the comment uuid" {
	run bash -c "'$REC' < $(comment_event mcp__Linear__save_comment CLOUD-42)"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == "comment CLOUD-42 2026-08-13T00:00:00.000Z - - - -" ]]
}

# The regression case, stated as a shape rather than a value: whatever a comment
# row carries, it is never a uuid. A uuid in an issue-key column reads as data
# rather than as a gap, which is worse than the gap — nothing downstream can tell
# them apart.
@test "REGRESSION: a comment row never records a uuid" {
	local target field
	for target in CLOUD-42 ""; do
		rm -f "$(record)"
		run bash -c "'$REC' < $(comment_event mcp__Linear__save_comment "$target")"
		[ "$status" -eq 0 ]
		# The id COLUMN, not the whole line: a key like CLOUD-42 contains `-4`, so
		# a uuid-shaped match over the line flags a correct row.
		field=$(awk '{print $2}' "$(record)")
		[[ "$field" == "-" || "$field" =~ ^CLOUD-[0-9]+$ ]]
	done
}

# A reply names only its parent thread, and a comment on a project or document is
# not a board row at all. Both are "could not look", which is the same distinction
# this recorder already draws for a verdict.
@test "a reply, or a comment on a non-issue parent, records a dash rather than a guess" {
	run bash -c "'$REC' < $(comment_event mcp__Linear__save_comment '' parentId)"
	[ "$status" -eq 0 ]
	run cat "$(record)"
	[[ "$output" == "comment - 2026-08-13T00:00:00.000Z - - - -" ]]
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
