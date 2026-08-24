#!/usr/bin/env bash
#MISE description="PostToolUse hook body: record what this branch put on the board, with the tracker's own verdict on whether a new row was refined"
#
# CLOUD-514, phase 1. Every gate here prices FAILING to record something —
# `finding-sink-check` fails a turn that cites evidence and writes nothing,
# `deferral-check` fails a PR that defers without naming an issue. Nothing prices
# the opposite. Filing satisfies all of them in seconds while finishing costs a
# diff, a suite and a landing, so for an agent under pressure the punt is not a
# temptation, it is arithmetic.
#
# THIS FILE GATES NOTHING. It is the sensor half, and shipping a sensor alone is
# normally the "log without a gate" non-negotiable 2 refuses. The exception is
# argued and measured: the gate's firing rate cannot be estimated retrospectively
# because WHICH BRANCH PUT WHICH ROW ON THE BOARD has never been recorded
# anywhere. The one available proxy — rows created between a PR opening and its
# merge — was measured over 40 merged PRs and fires on 183 of 184, because a
# window over a fleet captures every session's filings. So this record is what
# makes the gate specifiable at all, and its enabling trigger is a number this
# produces rather than a date.
#
# WHY THE LINT HAPPENS HERE, WHICH IS THE WHOLE DESIGN. The first draft had the
# agent run `ready-lint` and mint a receipt. That is worthless: `ready-lint` reads
# a payload the caller assembles, and it was run three times during this issue's
# own refinement against text in a local file — once under the id `CLOUD-NEW`,
# for a row that did not exist — green every time. A toll payable in text nobody
# filed is not a toll. A `PostToolUse` body does not have that problem: it fires
# on the tool RESULT, which is the tracker's response to the create.
#
# THE RESULT ENVELOPE IS MEASURED, NOT ASSUMED. No hook in this tree had ever
# read a tool result, and the documented example is a `Write` whose response is a
# flat object. An MCP tool's is not: it is the content-block list
# `[{"type":"text","text":"<the row as JSON>"}]`, so `.tool_response.id` does not
# exist and a body written against the documented shape would silently record
# nothing.
#
# RELATIONS COME FROM THE INPUT, AND THAT IS NOT A COMPROMISE. `ready-lint`'s §8
# rule cross-checks prose claiming `blockedBy CLOUD-N` against the payload's
# relations, and the create response carries no relations at all — so linting the
# response alone reports `blocker-cited-without-relation` on exactly the rows that
# were refined most carefully. The create call's own `blockedBy` argument is the
# entire relation set on a create (there is nothing prior to append to), so it is
# what the tracker acted on. The BODY being judged is still the tracker's; naming
# a blocker is what creates the relation, so this cannot claim a dependency the
# board does not have.
#
# POINTER-ONLY IS LOAD-BEARING HERE (non-negotiable 4), not decorative: the text
# this reads is the entire issue body. Five fields reach the file — kind, id,
# updatedAt, verdict, the named paths, and the rows the stored body cites that the
# caller passed as no relation (CLOUD-923) — and nothing is ever printed.
#
# THE FIFTH FIELD IS PHASE 3 (CLOUD-514), and it is what the first two phases
# left out. The `verdict` column prices REFINEMENT: it asks whether the new row
# was written to Ready. It cannot ask the question the issue's acceptance is
# actually about — whether the row names code THIS BRANCH IS HOLDING OPEN —
# because a Ready block is prose, and prose is the one currency an agent has
# without limit. Measured 2026-08-20 on this branch: four rows filed in three and
# a half minutes, twelve more spent writing four Ready blocks, and every one
# recorded `ready`. The toll did not reverse the arithmetic; it certified it.
#
# So the overlap column records how many paths the row's body names that
# `origin/main...HEAD` is also changing — `mise-tasks/board-diff-overlap.sh`, which
# owns the predicate and its measurement. It is recorded for a groom as well as a
# create, for the same reason the verdict is: a later reading of the same row by
# the same mechanism is simply the current one. Pointer-only holds by
# construction there — only paths tracked in this repository can appear.
#
# FAILS OPEN AND SILENT on everything it cannot establish. A recorder that
# blocked or noised a board write would cause the failure `finding-sink-check`
# exists to catch, which is the opposite of the point.
#
# The mutation widens the exception below to every update, so an edit to any
# existing row — anyone's — is recorded as a filing, which inflates the very count
# the gate is specified against, in the direction that makes filing look normal.
#MUTANT any-update-recorded|s/^\t\t\t\tgrep -qE .*$/\t\t\t\ttrue; then/|a groom of a row this branch did NOT file is still skipped
# The mutation removes the one exception to that, so a groom of a row THIS branch
# filed goes unrecorded again — which leaves the creation-time verdict standing
# and `filed-here-check`'s third remedy unreachable, the state that held PR #525.
#MUTANT never-records-a-groom|s/^\t\t\t\tfiled_here=1$/\t\t\t\tfiled_here=/|a groom of a row THIS branch filed is recorded
# The mutation drops the relations synthesis, so a row whose §8 claims a blocker
# lints as blocker-cited-without-relation and records `unready` — the false
# refusal that would fire on the best-refined rows.
# The mutation restores the shipped defect: synthesise on the update path too, so
# a groom that adds a correct §8 clause is the write that records `unready` —
# `filed-here-check` refusing the remedy it advertises (CLOUD-781).
#MUTANT groom-synthesises-relations|s/^\tif \[\[ -z "\$existing" \]\]; then$/\tif true; then/|a groom whose §8 cites a blocker is unjudgeable, not unready
#MUTANT relations-dropped|s/relations: \$rels/relations: {}/|claims a blocker still records a green verdict
# The mutation restores the shipped defect: take the id from the response for a
# comment too, so an issue-key column fills with comment uuids and sink 2 becomes
# unobservable while every count still looks right.
#MUTANT comment-id-from-response|s/^if \[\[ "\$kind" = comment \]\]; then$/if false; then/|records the issue key its input names
# The mutation stops asking the diff question at all, so every row records `-`
# and `filed-here-check` reads "could not look" for a row filed straight over the
# branch's own open files — phase 3 wired shut while every count still looks right.
#MUTANT overlap-never-measured|s/^\t\toverlap=\$(printf .*$/\t\toverlap=-/|a row whose body names a changed file records a non-zero overlap
# The mutation drops `--named`, so the column falls back to the write-time
# intersection — which is `0` for every row filed before its file is touched, the
# defect CLOUD-774 exists to remove. Only a case that files with an EMPTY diff and
# then checks can catch it.
# `--n[a]med` is a character class on purpose: written literally, the pattern
# matches THIS LINE, so every run rewrote the declaration instead of the call,
# came back non-inert, and survived. `mutant` refuses that shape as
# `self-mutating-row` since CLOUD-480; the class is how a row names a string it
# must also contain.
#MUTANT overlap-frozen-at-write-time|s@ --n[a]med @ @|A FILE THIS BRANCH HAS NOT TOUCHED IS STILL RECORDED
#
# CLOUD-923's column, and the mutation is the one that passes every other row: read
# the citations from the caller's ARGUMENT instead of the tracker's response, so a
# caller that strips them from what it sends records zero over a body that carries
# eight. Anchored on `^if`, so it cannot match its own `#MUTANT` line and is
# not the self-mutating shape `mutant` refuses since CLOUD-480.
# THIS DECLARATION WENT STALE UNDER ITS OWN AUTHOR (CLOUD-941's class, one commit
# apart): it targeted the `-n "${description:-}"` guard, and CLOUD-806 replaced that
# guard with `-n "$emitted"` when the keys moved to `ready-lint`'s emission. `sed`
# does not call "matched zero lines" an error, so `mutant` reported it `inert` rather
# than passing — which is the verdict working, and the reason a declaration must be
# re-read whenever the line it names is edited.
#MUTANT cites-read-from-the-argument|s@^if \[\[ "$kind" = issue \]\] && \[\[ -n "$emitted" \]\]; then@if false; then@|a write records the rows its stored body cites
set -uo pipefail

#
# CLOUD-479's pairing, declared rather than discovered. This hook is registered
# BY PATH, so it does not get mise's env and the `"aqua:jqlang/jq"` pin below
# does not reach it — `jq` is whatever the ambient PATH holds, or nothing. Every
# read here is fail-open, so an absent `jq` would not error: it would ALLOW,
# silently, which is the one outcome a guard must never reach by accident.
#
# Asserted loudly and still open. A `PreToolUse` hook's exit 2 is a DENY, so a
# missing parser must not take that channel — it says so on stderr and gets out
# of the way, which is loud where it used to be silent while never blocking a
# call over a broken toolchain.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: board-write-record: no jq on PATH — this guard is registered by path, so it does not get mise's pinned jq. It is checking NOTHING and allowing every call. Run: mise install" >&2
	exit 0
fi

[[ -n "${BATTEN_BOARD_WRITE_BYPASS:-}" ]] && exit 0

raw=$(cat) || exit 0

tool=$(printf '%s' "$raw" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[[ -n "$tool" ]] || exit 0

# Suffix, never prefix. CLOUD-178 measured the same connector exposed as
# `mcp__Linear__save_issue`, `mcp__<uuid>__save_issue` and
# `mcp__claude_ai_Linear__save_issue` depending on the registration episode, so a
# rule naming one matches none of the others and the miss is silent. The settings
# matcher is anchored the same way; this is belt to its braces.
case "$tool" in
*save_issue) kind=issue ;;
*save_comment) kind=comment ;;
*) exit 0 ;;
esac

# An `id` in the INPUT means this updates a row that already exists, which is not
# a board write this branch is answerable for. `finding-sink-check` already tells
# the two apart this way.
#
# ONE EXCEPTION, AND WITHOUT IT `filed-here-check`'S THIRD REMEDY IS UNREACHABLE
# (CLOUD-514). That gate tells a branch which filed an unrefined row to "groom
# the row above to Ready and re-run `land`" — but a groom is a `save_issue` WITH
# an id, so this skipped it, the record kept its creation-time `unready`, and the
# gate refused forever. Measured 2026-08-19 on PR #525: the row was groomed until
# `ready-lint` exited 0 over the tracker's own response, and the refusal did not
# move. Remedies 1 and 2 fail the same way once a line exists, so the only escape
# was the bypass — which the gate's own bats suite does not scrub, so exporting it
# turned six refusal cases into passes.
#
# The exception is narrow on purpose: an update is recorded only when this
# branch's record already carries an `issue` line for that id. That is the row
# this branch filed and is answerable for, so re-linting it grants nothing a
# fresh create would not have granted, and the verdict still comes from linting
# the tracker's RESPONSE rather than from any caller's assertion. An update to
# somebody else's row is skipped exactly as before.
existing=""
if [[ "$kind" = issue ]]; then
	existing=$(printf '%s' "$raw" | jq -r '.tool_input.id // empty' 2>/dev/null) || exit 0
	if [[ -n "$existing" ]]; then
		filed_here=""
		if here_dir=$(git rev-parse --git-dir 2>/dev/null) && [[ -n "$here_dir" ]] &&
			here_branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) &&
			[[ -n "$here_branch" ]]; then
			here_record="$here_dir/batten-receipts/board-writes.${here_branch//\//-}"
			# Anchored on the kind and the whole id field, so `CLOUD-71` never
			# matches the `CLOUD-717` line beside it.
			if [[ -r "$here_record" ]] &&
				grep -qE "^issue ${existing} " "$here_record" 2>/dev/null; then
				filed_here=1
			fi
		fi
		[[ -n "$filed_here" ]] || exit 0
	fi
fi

# The content-block envelope, per the measurement in the header. `fromjson?`
# rather than `fromjson` so a text block that is not JSON is skipped instead of
# aborting the whole read.
row=$(printf '%s' "$raw" | jq -c '
	[ .tool_response[]? | select(.type == "text") | .text | fromjson? ] | first // empty
' 2>/dev/null) || exit 0
[[ -n "$row" ]] || exit 0

# THE ID COLUMN IS AN ISSUE KEY, AND FOR A COMMENT THE RESPONSE CANNOT SUPPLY
# ONE. Measured on this recorder's own first five live rows, which came out as
# `comment 4d16245a-43ea-49ae-b67d-c2ee0b64b96e …` — the comment's own uuid. A
# `save_comment` response is the COMMENT object: its `.id` is the comment, and it
# carries no reference to the row the comment landed on. Taking `.id` for both
# kinds therefore silently fills an issue-key column with uuids, and sink 2's
# whole definition — a comment on the row that already owns the finding — becomes
# unobservable.
#
# The key is in the INPUT instead, as the parent reference. `issueId` is the only
# parent that is a board row; a reply carries `parentId` and no `issueId` (the
# thread determines the issue, which this hook cannot see), and a comment on a
# project, document or milestone is not a row at all. Both record `-`, the same
# "could not look" this file already draws for a verdict.
#
# NEVER FALL BACK TO THE COMMENT UUID. A uuid in an issue-key column is a wrong
# answer wearing a right answer's shape, and it reads as data rather than as a
# gap — which is strictly worse than the gap, because nothing downstream can tell
# the two apart.
if [[ "$kind" = comment ]]; then
	id=$(printf '%s' "$raw" | jq -r '.tool_input.issueId // "-"' 2>/dev/null) || id=-
else
	id=$(jq -r '.id // empty' <<<"$row" 2>/dev/null) || exit 0
	[[ -n "$id" ]] || exit 0
fi
[[ -n "$id" ]] || id=-
updated=$(jq -r '.updatedAt // "-"' <<<"$row" 2>/dev/null) || updated=-

git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0
[[ -n "$git_dir" ]] || exit 0
branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || exit 0
[[ -n "$branch" ]] || exit 0

# A comment is sink 2 — recorded so the create-versus-comment ratio is
# observable, never judged. Only a new row carries a refinement obligation.
verdict=-
if [[ "$kind" = issue ]]; then
	# ALL THREE DIRECTIONS, NOT JUST `blockedBy` (CLOUD-774). `ready-lint`'s
	# `deferral-cited-without-relation` scans the whole description and accepts ANY
	# relation direction, and its header says why: demanding `blockedBy`
	# specifically "would push authors to declare false dependencies to pass a
	# lint". Synthesising only `blockedBy` reintroduced exactly that pressure from
	# the other side — a row that honestly records a hand-off as `relatedTo`, the
	# direction that rule calls the common case, linted `unready` here while
	# passing when a human ran `ready-lint` by hand. Measured 2026-08-20: CLOUD-769
	# recorded `unready` through four grooms for this and nothing else.
	# AND ONLY ON A CREATE (CLOUD-781). The argument is the whole relation set
	# exactly once in a row's life: at creation, when there is nothing prior to
	# append to. `save_issue` relations are APPEND-ONLY, so on an update the
	# argument is a patch — a groom that touches only the body passes no
	# `blockedBy` at all, and `[.tool_input.blockedBy[]?]` over an absent key
	# yields `[]`. Synthesising that hands `ready-lint` a payload asserting THIS
	# ROW HAS NO BLOCKERS, which is a claim nothing here checked, and under
	# CLOUD-679's rule an empty-but-present key is an ANSWER — correctly believed.
	# The defect is the assertion, not the gate.
	#
	# Measured 2026-08-20, one row, three writes: a groom whose §8 cited a real
	# blocker recorded `unready`, and the identical body re-saved with
	# `blockedBy` restated — a no-op against the tracker — recorded `ready`. The
	# relation was on the tracker throughout; only this could not see it. So
	# `filed-here-check` refused the lap of a branch that filed a row and then
	# groomed it to Ready, which is that gate's own third remedy: the toll
	# refusing the remedy it exists to reward.
	#
	# OMIT THE KEY, never synthesise a thinner one. There is no richer answer
	# available — the update response carries no relations and a hook holds no
	# tracker credential, the same bound `claim-check` documents — so the honest
	# answers are "could not look" or a wrong one. Omitting fires
	# `unjudgeable-relations`, this records `-`, and `filed-here-check` passes `-`
	# by design. Three-valued, composing with the sibling gate rather than
	# duplicating it.
	if [[ -z "$existing" ]]; then
		rels=$(printf '%s' "$raw" | jq -c '{
		  blockedBy: [.tool_input.blockedBy[]? | {id: .}],
		  blocks: [.tool_input.blocks[]? | {id: .}],
		  relatedTo: [.tool_input.relatedTo[]? | {id: .}]
		}' 2>/dev/null) || rels='{"blockedBy":[],"blocks":[],"relatedTo":[]}'
		payload=$(jq -c --argjson rels "$rels" '{
		  id: .id,
		  description: (.description // ""),
		  relations: $rels
		}' <<<"$row" 2>/dev/null) || payload=""
	else
		payload=$(jq -c '{
		  id: .id,
		  description: (.description // "")
		}' <<<"$row" 2>/dev/null) || payload=""
	fi
	# BY PATH, AND THE STATUS IS READ AS THREE ANSWERS RATHER THAN TWO.
	#
	# `mise run ready-lint` is the obvious call and is wrong here: a hook inherits
	# the cwd of the tool call, which is not required to be inside this project,
	# and `mise run` outside a project errors out. That failure is silent and it
	# lands on the WRONG side — mapping any non-zero to `unready` would record a
	# refusal for every row filed from a directory mise could not resolve, which
	# is a verdict about the environment wearing the mask of a verdict about the
	# row. Sibling tasks are addressed relative to this file for that reason.
	#
	# `ready-lint`'s contract is 0 pass / 1 the block is wrong / 2 the input could
	# not be read OR could not be judged, so only 1 is a judgement. Anything else
	# — 2, or a 127 from a missing interpreter — leaves the verdict `-`, which the
	# gate reads as "not answered" rather than as a refusal. Since CLOUD-781 the
	# update path reaches that 2 DELIBERATELY rather than only by accident: it
	# omits the relations key, `unjudgeable-relations` fires, and `-` is the
	# honest answer for a groom whose relations nothing here can see.
	if [[ -n "$payload" ]]; then
		# STDOUT IS KEPT NOW (CLOUD-806). `ready-lint` emits the structure it already
		# built — `cites-body` and `cites-blockers` — before it branches on a verdict,
		# so this reads the derived fact instead of rebuilding it with a second regex
		# over the same body. stderr still goes nowhere: its pointers are the lint's
		# own report, and this file prints nothing.
		lint_out=$(printf '%s' "$payload" | "$(dirname -- "${BASH_SOURCE[0]}")/ready-lint.sh" 2>/dev/null)
		case $? in
		0) verdict=ready ;;
		1) verdict=unready ;;
		*) verdict=- ;;
		esac
	fi
fi

# THE NAMED-PATHS COLUMN, which until CLOUD-774 held the write-time INTERSECTION
# and was renamed with the meaning. `-` is "could not look" here exactly as it is
# for the verdict: outside a checkout, or a body the tracker did not return. It is
# no longer "no `origin/main`" — `--named` needs only `git ls-files`, so a fresh
# clone records the row instead of losing it.
#
# WHY THE COLUMN CHANGED MEANING. An intersection is a fact about the diff at the
# instant the row was written, and rows are routinely written before any file is
# touched — AGENTS.md tells you to claim before writing code, so the compliant
# order produced `0` every time and `filed-over-own-diff` could never see the punt
# it was built for. What a row is ABOUT does not decay; `filed-here-check` does
# the intersection when it is asked instead.
#
# The description read is the tracker's RESPONSE, not the caller's argument, so it
# is unforgeable for the same reason the verdict is.
overlap=-
if [[ "$kind" = issue ]]; then
	description=$(jq -r '.description // empty' <<<"$row" 2>/dev/null) || description=""
	if [[ -n "$description" ]]; then
		overlap=$(printf '%s' "$description" | "$(dirname -- "${BASH_SOURCE[0]}")/board-diff-overlap.sh" --named 2>/dev/null) || overlap=-
	fi
	[[ -n "$overlap" ]] || overlap=-
	# ONE COLUMN, ONE WHITESPACE-FREE TOKEN (CLOUD-923). `board-diff-overlap
	# --named` emits `<count> <path>...`, so this column was the only variable-width
	# one — and a record whose fifth field can swallow the rest of the line cannot
	# have a sixth. `filed-here-check` already comma-joined it on read (`packed`),
	# so the value it computes is unchanged; what moves is where the join happens.
	# Without this, the cites column below lands inside the named-path list and the
	# gate refuses a lap over a path called `0`.
	#
	# THE ONE-WAY COST, stated rather than papered over with a back-compat claim
	# this cannot honour: a record line written by the PREVIOUS shape carries the
	# space-separated form, so `filed-here-check` reads its second and later paths
	# into the cites column and judges the row on fewer named paths than it named.
	# That direction cannot manufacture a refusal — it can only miss one — and the
	# window is bounded by the store, which lives under `$GIT_DIR`, is never
	# committed, and dies with the container. Writer and reader ship in one commit.
	overlap=${overlap// /,}
fi

# ─── THE SEVENTH COLUMN: THE PATHS §1 NAMES (CLOUD-854) ──────────────────────
#
# The fifth column holds every path the BODY names, and `filed-over-own-diff`
# refuses on it. Measured four times, that predicate cannot tell a row claiming
# work on a file from a row CITING it as evidence: "measured on X" and "I will fix
# X later" produce identical input to a path-name intersection. So the gate fires
# hardest on the rows that document their provenance best — the property
# CLOUD-732 exists to REQUIRE — and two gates end up pulling opposite ways.
#
# The subject is recoverable without judging prose, because a Ready block's §1
# names the source of truth by construction. This column is the §1 clause's paths
# alone, and `filed-here-check` intersects the two: a row is refused only where a
# path is both in the diff AND in its own §1.
#
# ONE EXTRACTOR, NOT TWO. The span is narrowed here and handed to the SAME
# `board-diff-overlap --named` that computes the fifth column, so basename
# resolution, the ambiguity rule and the tracked-only bound cannot drift into a
# second authority. `-` keeps its meaning: no §1, no body, or a span this could
# not read is "could not look", and `filed-here-check` passes such a row rather
# than refusing on a question the recorder could not ask.
#
# The clause grammar is `ready-lint`'s CLAUSE_LABEL — a bolded label or a heading
# carrying the tag — because a Ready block has exactly one definition of where a
# clause begins, and a second reading of it here is the drift CLOUD-290 records.
sec1=-
if [[ "$kind" = issue ]] && [[ -n "${description:-}" ]]; then
	span=$(awk '
		/^[[:space:]]*([*-][[:space:]]*)?\*\*[^*]*\((§|clause )[0-9]+\)|^#{2,6}[[:space:]]+[^#]*\((§|clause )[0-9]+\)/ {
			# A clause label ends the §1 span and starts a new one, so `in_s1`
			# is re-decided on every label rather than only on the first.
			in_s1 = ($0 ~ /\((§|clause )1\)/) ? 1 : 0
		}
		in_s1 { print }
	' <<<"$description" 2>/dev/null) || span=""
	if [[ -n "$span" ]]; then
		sec1=$(printf '%s' "$span" | "$(dirname -- "${BASH_SOURCE[0]}")/board-diff-overlap.sh" --named 2>/dev/null) || sec1=-
	fi
	[[ -n "$sec1" ]] || sec1=-
	sec1=${sec1// /,}
fi

# THE CITED-KEYS COLUMN (CLOUD-923). The tracker auto-links every `CLOUD-nnn`
# mention in a body into a symmetric `relatedTo` edge, so writing a body modifies
# every row it cites — rows the caller passed as no parameter, named as no
# relation, and is told about in no response. Measured over one grooming session:
# 43 edges added, 11 passed, 32 minted by prose, and therefore 32 rows outside the
# session's scope silently modified. Nothing saw it: `graph-check` reads
# `relatedTo` for nothing at all, and this recorder had five columns and no
# relation term.
#
# ─── WHAT THIS COLUMN IS, AND WHAT IT IS NOT ─────────────────────────────────
#
# CLOUD-923 §1 says the pre-write set is in the `issue-read-check` payload and the
# post-write set is in the `save_issue` response, so an observed DELTA needs no new
# fetch. BOTH HALVES ARE FALSE, measured 2026-08-23 rather than assumed:
#
#   * a `save_issue` response carries no `relations` key at all — only
#     `get_issue(includeRelations: true)` does, and a hook holds no tracker
#     credential to make that call (`claim-check`'s constraint);
#   * `issue-read-check`'s receipt is `key seen read_at body_hash seen_status` —
#     five fields, no relation set. The payload had one; the receipt did not keep
#     it.
#
# So the observed delta is not computable here without the fetch §1 forbids. What
# IS in hand is the caller's arguments and the body the tracker STORED, and their
# difference is the set of edges prose will mint: **the keys the stored body cites
# that the caller passed as no relation.**
#
# That is a PREDICTION, not an observation, and the difference is stated rather
# than absorbed: a cited row that was already related is counted here and adds no
# edge, so this OVER-counts and never under-counts. Conservative in the direction
# CLOUD-923 §2 asks for — the failure mode it names is the record being quieter
# than the truth, and an upper bound cannot be that.
#
# Unforgeable for the same reason the verdict and the named-paths column are: the
# body read is the tracker's RESPONSE, never the caller's argument. A caller who
# strips citations from what it SENDS still gets them counted from what came back.
#
# Pointer-only per non-negotiable rule 4: a count and the far-end keys,
# comma-joined so the record stays one field per column. Never a line of the body
# that minted them.
#
# THE KEYS COME FROM `ready-lint`, NOT FROM A SECOND SCAN (CLOUD-806). This file
# already spawns that gate on this very body, and that gate is the one program in
# the tree that turns a Ready block into structure — it strips Linear's
# `<issue …>` mention markup, dedupes, and orders numerically. A second regex here
# would be a second authority over one question, and the two would disagree the
# first time either was touched.
#
# ABSENT IS "COULD NOT LOOK", NEVER EMPTY. The producer emits the line BEFORE it
# branches on a verdict, so a missing line means it exited before reaching the
# emission — an unreadable payload — and this column stays `-`. A line that is
# PRESENT and carries no keys is the honest zero. Collapsing those two is the
# CLOUD-251 shape the overlap column above already takes care to avoid.
#
# REPORTED, NEVER REFUSED, and that is CLOUD-923's open call decided. The tracker's
# auto-linking is not the author's choice and no body can opt out of it, so a
# refusal would be a toll with no remedy — the shape `filed-here-check`'s own
# header warns about. This file prints nothing and moves no exit code regardless;
# what changes is that a later reader can see which far-end rows a branch touched.
cites=-
# The guard is the EMISSION, not the description: `ready-lint` is the producer, so
# "did it get far enough to emit" is the only thing that decides whether this
# column can be computed at all (CLOUD-806).
emitted=""
cited=""
if [[ -n "${lint_out:-}" ]]; then
	while IFS= read -r line; do
		[[ "$line" == cites-body* ]] || continue
		emitted=1
		cited=$(tr ' ' '\n' <<<"${line#cites-body }" | grep -vx '' || true)
		break
	done <<<"$lint_out"
fi
if [[ "$kind" = issue ]] && [[ -n "$emitted" ]]; then
	# The caller's arguments, all three directions: a row passed as a blocker is
	# not "minted by prose" however the body also mentions it.
	passed=$(printf '%s' "$raw" | jq -r '
		[ .tool_input.relatedTo[]?, .tool_input.blockedBy[]?, .tool_input.blocks[]? ]
		| map(select(type == "string")) | unique | .[]
	' 2>/dev/null) || passed=""
	minted=""
	while IFS= read -r k; do
		[[ -n "$k" ]] || continue
		# The row's own key is not an edge to anywhere.
		[[ "$k" != "$id" ]] || continue
		grep -qxF -- "$k" <<<"$passed" && continue
		minted="${minted:+$minted,}$k"
	done <<<"$(sort -t- -k2,2n <<<"$cited")"
	# ZERO IS A COUNT; `-` IS "COULD NOT LOOK". A body the tracker did not return
	# leaves the initialiser above standing, so the two are distinguishable in the
	# record — CLOUD-251's split, which this column would otherwise collapse in the
	# quiet direction.
	if [[ -z "$minted" ]]; then
		cites=0
	else
		cites="$(($(tr -cd , <<<"$minted" | wc -c) + 1)):$minted"
	fi
fi

mkdir -p "$git_dir/batten-receipts" 2>/dev/null || exit 0
# Slashes are the one character a filename cannot carry; the substitution matches
# every other branch-keyed receipt here.
record="$git_dir/batten-receipts/board-writes.${branch//\//-}"
printf '%s %s %s %s %s %s %s\n' "$kind" "$id" "$updated" "$verdict" "$overlap" "$cites" "${sec1:--}" >>"$record" 2>/dev/null || exit 0

exit 0
