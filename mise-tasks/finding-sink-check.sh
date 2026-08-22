#!/usr/bin/env bash
#MISE description="Gate: a turn that cites path:line evidence and makes no durable write stranded a finding (reads a transcript path on stdin; pointer-only)"
#
# CLOUD-252, the unmet first acceptance bullet of CLOUD-248: "a turn that states a
# finding in prose and makes no durable write is reported". The shipped
# `stop-posture-check` catches the finding written TWICE — once durably, once as
# editorial. This catches the opposite and worse case: the finding written
# NOWHERE, which dies with the chat.
#
# Two inputs, two predicates, nothing shared to drift: that one reads
# `last_assistant_message` and matches a literal set; this one reads the
# transcript and joins prose against the turn's own `tool_use` records. The
# transcript is what makes the join possible at all — `last_assistant_message`
# carries only the final text block (measured: 26,893 of 60,916 assistant-prose
# characters, and under 10% on 7 turns), so a finding stated mid-turn is invisible
# to that field by construction.
#
# ONE SHAPE, AND IT IS MEASURED. CLOUD-252 specified three; over a real 113-turn
# transcript, restricted to turns with no durable write:
#
#   path:line citation   1 firing  — the true positive          KEEP
#   exit N / EXIT= claim 2 firings — and the only false positive DROP
#   fenced command block 0 firings — never fires at all          DROP
#
# The exit-claim shape fires on an ordinary status summary ("… filed, fixed,
# gated green"), which every working session produces constantly. The fenced
# shape fires on nothing, and a branch nothing exercises is the dead code
# CLOUD-235 already cost this repo. So the predicate is a `path:line` citation
# and nothing else — one shape that fired once, correctly, on a turn whose two
# findings were filed several turns later.
#
# NO "ALREADY FILED" EXEMPTION, deliberately. CLOUD-248 wanted a turn discussing
# an already-filed finding exempted, and the obvious rule — cites a CLOUD-<n>, so
# skip — SUPPRESSES THE TRUE POSITIVE: that turn cites three issue keys while
# stating two unfiled findings. Measured, not reasoned. An exemption that silences
# the one case a gate exists for is worse than no exemption.
#
# POINTER, NEVER PAYLOAD — and here that is not a privacy rule, it is the
# mechanism. Handing the matched prose back would return the agent's own sentences
# to it as input, and a mirror can be cleared by RESTATING, which is the exact
# double-write CLOUD-200 and CLOUD-248 exist to kill. A coordinate cannot be
# cleared that way: the only way to answer `turn:46` is to go look. The bare
# question "Done?" is the same shape and is what surfaced nine real findings in
# one session while carrying no information at all.
#
# MUTATION COVERAGE (CLOUD-418). `<slug>|<sed script>|<case name>`: applying
# the script to a throwaway copy of this file must turn the named case RED.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT class-split-removed|s@^OPENS_A_ROW=.*@OPENS_A_ROW='save_'@|CLOUD-475: a COMMENT alone is not a home

set -uo pipefail

transcript=$(cat) || exit 2
transcript="${transcript//[[:space:]]/}"
if [[ -z "$transcript" ]] || [[ ! -r "$transcript" ]]; then
	echo "::error:: no readable transcript path on stdin" >&2
	exit 2
fi

# A finding shape: a source citation with a line number. Two accepted forms, and
# the second is not optional here — half this repo's programs are the
# extensionless files under `mise-tasks/`, and a finding about one cites
# `mise-tasks/land.sh:200`. An extension-only anchor misses every one of them, which
# is most of the shell layer.
#
#   a/b:12          a path separator, which a bare "word:digits" lacks
#   thing.rs:12     a known source extension, for a bare filename
#
# Anchored rather than open so an arbitrary "word:digits" in prose — a duration
# (12:30), a ratio (3:1), a URL port — is not read as evidence. Those carry
# neither a separator nor an extension.
CITATION='([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+|[A-Za-z0-9_-]+\.(rs|toml|yml|yaml|bats|md|json|pkl|sh|lock)):[0-9]+'

# A durable write: the tracker or a memory. Matched on the tool-name SUFFIX, never
# the server prefix — the same connector appears as `mcp__Linear__save_issue` and
# as `mcp__<uuid>__save_issue` within one session (CLOUD-178), so a prefix anchor
# silently misses whichever name is live.
#
# RECORDED IS NOT SCHEDULED (CLOUD-475). One flat list counted `save_comment` as a
# home with no term for the TARGET'S STATE — so a turn that finds a defect in
# landed code, comments it onto the Done issue that shipped it, and files nothing
# scored durable and passed. The board then has no open row for it, no sweep
# visits it, and no gate notices: the finding is durably RECORDED and permanently
# UNSCHEDULED. The gate written to catch a stranded finding was cleared by the
# exact act that strands it.
#
# The naive fix — "refuse a comment on a Done issue" — LOOKED uncomputable here,
# and for one release it was: no tracker credential exists in a hook, exactly as
# it does not for `claim-check`, so the target's state cannot be FETCHED. The
# predicate keyed on the CALL SHAPE instead —
#
#   OPENS a row    `save_issue` with NO `id` — a created issue is open by
#                  construction, so this needs no state lookup at all.
#   ANNOTATES      `save_comment`, and `save_issue` WITH an `id`. Both attach to a
#                  row that already exists and MAY be terminal.
#
# — and "may be terminal" is where that proxy is wrong (CLOUD-775). It is right
# about the case it was built for and wrong about the symmetric one: adding the
# finding to a row that is still OPEN schedules the work exactly as filing does.
# The board carries it, a sweep visits it, `done-check` gates it. Reporting that
# as a stranding is the false positive that gets a gate bypassed, after which it
# enforces nothing.
#
# WHAT REPLACES THE PROXY IS NOT A FETCH — it is a file this clone already wrote.
# `issue-read-check` records the column it saw on every read, and
# `issue-read-guard` denies `save_issue` without a fresh receipt for that row, so
# by the time anything annotates a row a receipt for it EXISTS. `row_class` below
# reads its fifth field. The question stays uncomputable by lookup and becomes
# computable by record, which is the move `claim-check` already makes.
#
# THREE CLASSES, AND ONLY `open` IS NEW. `noid` is the created row, unchanged.
# `open` is an amendment to a row whose recorded column is one the board still
# carries. Everything else — a terminal column, an unrecognised one, a row with
# no receipt, a call outside a checkout — is NOT a home, and the collapse is
# deliberate: a row that could not be looked up must be indistinguishable IN
# EFFECT from a closed one, or "could not look" becomes the cheapest way to buy
# silence. The receipt's own `-` is on that side too, so a caller who reads a row
# while sending no status gains nothing by having sent less.
#
# Memory and document writes keep their current standing, deliberately: a memory
# is read on demand at its trigger, which is a different destination with a
# different reader, and this rule does not reopen that question.
#
# The names carry a `#<class>` suffix stamped by pass 2 and `row_class` below, so
# the classes are distinguishable without a second read of the transcript.
#
# The mutation drops the column from the open-row class, so it accepts any column
# at all — which reopens the hole from the other side: an annotation on a Done row
# reads as a home again and CLOUD-475's true positive dies. It rewrites the
# SUFFIX rather than the whole assignment because the alternation cannot survive
# the round trip — `mutant` splits its rows on `|`, so no script may contain one.
#MUTANT terminal-row-is-a-home|s@#open\$'@#'@|CLOUD-775: an annotation on a TERMINAL row still reports
OPENS_A_ROW='save_issue#noid$'
AMENDS_AN_OPEN_ROW='save_(issue|comment)#open$'
OTHER_DURABLE='(save_document|write_memory|edit_memory|rename_memory)#'

# The receipt store, resolved once. An absent git dir is a cannot-look for every
# row at once, and it lands on the not-a-home side with the rest of them.
git_dir=$(git rev-parse --git-dir 2>/dev/null) || git_dir=""

# The board's OPEN set is what is enumerated, never the terminal one. A column
# nobody here has heard of falls through to `terminal`, so a new board state
# cannot buy silence before someone has decided that it should.
row_class() { # row_class <key-or-empty> -> noid / open / terminal
	case "$1" in
	"") echo noid && return ;;
	[A-Z]*-[0-9]*) ;;
	*) echo terminal && return ;;
	esac
	[[ -n "$git_dir" ]] || { echo terminal && return; }
	column=$(awk 'NR==1{print $5}' "$git_dir/batten-receipts/issue-read.$1" 2>/dev/null) || column=""
	case "$column" in
	backlog | todo | in-progress | in-review) echo open ;;
	*) echo terminal ;;
	esac
}

# ONLY THE TURN THAT JUST ENDED, AND ONLY THAT TURN IS READ. Judging the whole
# transcript is what the first wiring did, and running it live exposed the defect
# immediately: it reported a turn from hours earlier whose findings had long since
# been filed, and it would have re-reported that same turn at every Stop for the
# rest of the session. A stale pointer is worse than none — it is unactionable, so
# it trains the reader to skip the channel, which is the failure this whole
# mechanism exists to avoid.
#
# At a turn boundary the only turn still actionable is the last one. Earlier turns
# were either already answered or already missed; neither is this nudge's business.
#
# THE COST THAT MADE THIS TWO PASSES (CLOUD-479). The first implementation built
# every turn's prose and tool map and then took `tail -n 1`, so the work behind
# every turn but one was discarded by design on every turn end, and it grew with
# session length. Measured over a real 2.9MB / 1237-line transcript: 338ms total,
# of which the slurp was 66ms. The slurp was never the cost — computing turns whose
# verdict is thrown away was. So the classifying pass reads the whole file and the
# per-block pass reads one turn, and only the cheap half grows.
#
# ONE RECORD PER LINE is a new and load-bearing assumption: pass 1 addresses the
# turn boundary by LINE, which a pretty-printed record would break. The harness
# writes JSONL and this task's own error text has always said so, so the assumption
# is stated here rather than left to be discovered.
#
# Main-thread only, on both passes. A subagent's write must never be credited to
# the orchestrator's turn, and its prose must never be judged as the
# orchestrator's — so `isSidechain == true` is dropped on both sides.

# PASS 1 — turn boundaries, streaming, no slurp. A turn opens at a real user
# prompt: a `tool_result` also arrives as a user record and is NOT a prompt, so
# counting it would split one turn into many and hand each fragment its own
# verdict. The COUNT of boundaries is the turn number — the last turn IS turn N —
# and the LAST boundary is the line the turn under judgement begins on.
if ! boundaries=$(jq -r '
    select(.isSidechain != true)
    | select(.type == "user")
    | select( (.message.content | type) == "string"
              or ( (.message.content | type) == "array"
                   and ( [ .message.content[] | select(type == "object" and .type == "text") ] | length ) > 0 ) )
    | input_line_number
  ' "$transcript" 2>/dev/null); then
	echo "::error:: transcript is not readable JSONL: $transcript" >&2
	exit 2
fi

turns=$(grep -c . <<<"$boundaries")
start=$(tail -n 1 <<<"$boundaries")

fired=0
if [[ -n "$start" ]]; then
	# PASS 2 — the last turn's assistant blocks only. Each block is tagged with one
	# leading character rather than collected into a record, so prose and tool names
	# stay separable without reading the slice twice.
	if ! blocks=$(tail -n +"$start" "$transcript" | jq -r '
	    select(.isSidechain != true)
	    | select(.type == "assistant")
	    | (.message.content // [])[]
	    | select(type == "object")
	    | if .type == "text" then "T" + ((.text // "") | gsub("\n"; " "))
	      elif .type == "tool_use" then "U" + (.name // "") + "#" +
	             ((.input // {}) | if type == "object"
	              then ((.id // .issueId // "") | tostring) else "" end)
	      else empty end
	  ' 2>/dev/null); then
		echo "::error:: transcript is not readable JSONL: $transcript" >&2
		exit 2
	fi

	prose=$(grep '^T' <<<"$blocks")
	tools=$(grep '^U' <<<"$blocks")

	# One opens-a-row write in the same turn clears it; so does a memory or
	# document write, whose standing is unchanged. An ANNOTATION alone does not
	# (CLOUD-475) — that is the whole of this rule.
	clean=0
	if [[ -n "$tools" ]]; then
		while IFS= read -r name; do
			[[ -n "$name" ]] || continue
			# Pass 2 stamped the ROW KEY after the `#`. Which column that row was in
			# is a fact about this clone's own receipts rather than about the
			# transcript, so it is resolved here and not there.
			name="${name#U}"
			name="${name%%#*}#$(row_class "${name#*#}")"
			# ONE alternation, not three greps joined by `||`. The classes stay
			# separate variables above because they are separate ideas and a
			# mutation row keys on each, but they are matched in a single pass —
			# `pipefail-grep-check` reads the `||` as a producer piped into an
			# early-exiting grep, and it is right to: under `pipefail` that shape
			# is how a MATCH comes to report failure.
			if grep -qE "($OPENS_A_ROW|$AMENDS_AN_OPEN_ROW|$OTHER_DURABLE)" <<<"$name"; then
				clean=1
				break
			fi
		done <<<"$tools"
	fi

	if [[ "$clean" = 0 ]] && grep -qE "$CITATION" <<<"$prose"; then
		# The whole output contract, in one line: a coordinate and a count. Never a
		# byte of `$prose` — that variable is read and never printed.
		echo "turn:$turns finding-without-durable-write"
		fired=$((fired + 1))
	fi
fi

# A transcript with no turns is exit 0, not a finding — but it is also not proof
# of anything, so it says so. Anti-vacuity: a gate that cannot fire must not be
# indistinguishable from one that found nothing.
if [[ "$turns" = 0 ]]; then
	echo "finding-sink-check: no turns in $transcript — nothing to judge" >&2
	exit 0
fi

[[ "$fired" = 0 ]] && exit 0
# THE REFUSAL NAMES THE PRACTICE, NOT THE RULE (CLOUD-475). "This is not durable"
# reproduces the confusion it is meant to clear, because an author who commented
# the finding onto its source issue correctly believes they wrote it down. What
# they are missing is an OPEN ROW, so that is what the message asks for.
echo "finding-sink-check: the last of $turns turn(s) cited path:line evidence and gave it no OPEN row. Writing to a row that is closed — or to one this clone has recorded no read of — records the finding without scheduling it. File an open issue for the work and link it \`relatedTo\` the source, or put it on a row that is still open, recording the read first with \`mise run issue-read-check\`." >&2
exit 1
