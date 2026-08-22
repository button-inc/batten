#!/usr/bin/env bash
#MISE description="Gate: does this host carry N independent session transcripts — the corpus condition every mined-prose literal rests on (pointer-only; two counts, never a path's content)"
#
# CLOUD-388. This repo holds prose-shaped predicates to one method: no literal
# ships until it is measured over a real corpus, counting firings AND true
# positives among them (CLOUD-252, followed by CLOUD-323 over 60 merged PR
# bodies). For PR bodies the corpus is GitHub and one API call. For SESSION
# TRANSCRIPTS there is no corpus, and the reason is the environment rather than
# anyone's oversight: transcripts are written inside the session's own ephemeral
# container and destroyed with it.
#
# MEASURED TWICE, SIX DAYS AND TWO CONTAINERS APART, SAME ANSWER:
#
#   2026-08-11   one .jsonl under the host root — the session doing the
#                measuring. Independent sessions: 0.
#   2026-08-17   one .jsonl, a different container. Independent sessions: 0.
#
# Nothing accumulates a corpus BY ITSELF: every session starts at N=1, its own,
# and ends at N=0. CLOUD-326's §8.1 states its unblock condition as "N independent
# session transcripts … from sessions this issue did not arise from", and a block
# written as prose is a block no gate reads. THIS FILE IS THAT CONDITION AS A
# COMMAND AND AN EXIT CODE, which is the whole of why it exists.
#
# WHAT THE READING MEANS, and this changed once (CLOUD-651). The first version of
# this header called the corpus impossible and told the reader that waiting raises
# nothing, because CLOUD-388's verdict had ruled transcript egress out of scope.
# That was a POLICY choice about what may leave the container, not a fact about
# the world, and the owner lifted it: transcripts are collected to the Batten
# service. So a refusal here is a PROGRESS READING — the collector has not landed,
# or has not yet reached this host — rather than a permanent state of affairs, and
# the number is expected to rise. Do not re-derive the old rule from a low count.
#
# WHAT IT DOES NOT DO, deliberately. It captures nothing, pushes nothing, and
# writes nothing — the collector is CLOUD-651's, this is only the reading. Keeping
# the sensor and the collector apart is what lets the corpus condition be checked
# on a host that has never run the collector at all.
#
# Usage: mise run transcript-corpus-check [min] [exclude-session-id]
#
#   min                    how many independent sessions the condition needs.
#                          Default 2 — see the constant below for why that
#                          number and not a larger one.
#   exclude-session-id     the asking session, which is not independent evidence
#                          about itself. Defaults to $BATTEN_SESSION_ID when the
#                          host sets one; empty excludes nothing.
#
# Exit 0 the condition holds, 1 it does not, 2 the question could not be asked
# (house style §7). Exit 2 is reachable only from a genuinely unreadable root or
# a malformed argument — never from a path that has looked and found nothing,
# because "no transcripts here" is an answer and must not be reported as a
# failure to look.
set -uo pipefail

# THE DEFAULT IS THE WEAKEST NON-VACUOUS THRESHOLD, on purpose. Two is "more than
# the session asking", which is the least this can demand and still mean
# anything. A larger constant would look more rigorous and decide nothing extra:
# the measured count is 0 on every container this has run on, so every threshold
# from 1 upward returns the same verdict. Picking 60 to mirror CLOUD-323's PR
# corpus would be a number nobody could reach and nobody had measured — which is
# the shape of unfalsifiable decoration, not of a bound.
DEFAULT_MIN=2

usage() {
	echo "usage: transcript-corpus-check [min] [exclude-session-id]" >&2
	exit 2
}

# `${1-…}` rather than `${1:-…}`, for the same reason the exclusion below uses
# the same form: an argument that is PRESENT and empty is a caller passing
# something, not a caller passing nothing. Defaulting it would launder a
# malformed call into a verdict; reaching the numeric test below refuses it.
min="${1-$DEFAULT_MIN}"
# `${2-}` rather than `${2:-}`: an explicitly EMPTY second argument is a caller
# saying "exclude nothing", and it must not silently fall back to the ambient
# session id. Absent and empty are different claims here for the same reason
# `lint.rs` says absent is not empty.
if [[ "$#" -ge 2 ]]; then
	exclude="$2"
else
	exclude="${BATTEN_SESSION_ID:-}"
fi
[[ "$#" -le 2 ]] || usage

case "$min" in
'' | *[!0-9]*) usage ;;
esac

# INJECTABLE, and that is what makes this testable at all. A live host produces
# exactly one count — its own session — so a suite that could not vary the root
# would ship as coverage while exercising a single row (CLOUD-418). The default
# is the host's own layout, which is a HOST fact rather than a consumer one, so
# it is fine here in the task layer and would not be fine in `crates/batten`
# (non-negotiable rule 1).
root="${BATTEN_TRANSCRIPT_ROOT:-$HOME/.claude/projects}"

if [[ ! -d "$root" ]]; then
	echo "::error:: transcript-corpus-check: no transcript root at $root — the corpus question could not be asked" >&2
	exit 2
fi

#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: transcript-corpus-check: no jq on PATH — the corpus question could not be asked. Run: mise install" >&2
	exit 2
fi

# WHAT COUNTS AS INDEPENDENT, and why it is not "one file, one session".
#
# A transcript is independent evidence when it belongs to a DIFFERENT session
# that a person actually drove. Two things therefore do not count:
#
#   a subagent stream — `isSidechain: true` throughout. CLOUD-326's §8.1 recorded
#   "one session plus five subagent transcripts" and correctly called that N=1;
#   counting the five would inflate the corpus with the orchestrator's own turns
#   wearing different file names.
#
#   the asking session — excluded by id below. A literal fitted to the single
#   transcript it was derived from is the unmeasured-shape failure the method
#   exists to prevent, so counting yourself is worse than counting nothing.
#
# The boundary test is `finding-sink-check`'s pass 1, reused rather than
# re-derived: a `type == "user"` record that is not a sidechain and carries
# authored content (a bare string, or a block array holding at least one `text`
# block). A `tool_result` also arrives as a user record and is the harness
# handing work back, not a person speaking.
#
# `fromjson?` rather than plain jq over the file: the format is a HOST's and it
# moves, so a line this build cannot decode must yield nothing rather than turn
# the whole count into "could not look". That is `transcript.rs`'s
# forward-compatibility law, applied at the same boundary from the shell side.
BOUNDARY='fromjson?
  | select(type == "object")
  | select(.isSidechain != true)
  | select(.type == "user")
  | select( (.message.content | type) == "string"
            or ( (.message.content | type) == "array"
                 and ( [ .message.content[]? | select(type == "object" and .type == "text") ] | length ) > 0 ) )
  | .sessionId // empty'

independent=0
seen=""

# `find | sort` for byte-stability (§6): the same root yields the same count and
# the same verdict however the filesystem chose to order itself.
while IFS= read -r file; do
	[[ -n "$file" ]] || continue
	# No pipeline, and that is deliberate: `jq … | head -n1` would exit early,
	# signal the producer, and under `pipefail` promote a successful read to a
	# failure status — the shape `pipefail-grep-check` refuses one command over.
	# The first id is taken with a parameter expansion instead.
	ids=$(jq -R -r "$BOUNDARY" "$file" 2>/dev/null) || ids=""
	id=${ids%%$'\n'*}
	# No authored, non-sidechain user record anywhere in the file: a subagent
	# stream, or a transcript of something that never had a person in it.
	[[ -n "$id" ]] || continue
	[[ -n "$exclude" ]] && [[ "$id" = "$exclude" ]] && continue
	# Distinct sessions, not distinct files — a host that splits one session
	# across two files must not read as two.
	case "$seen" in
	*"|$id|"*) continue ;;
	esac
	seen="$seen|$id|"
	independent=$((independent + 1))
done < <(find "$root" -type f -name '*.jsonl' 2>/dev/null | sort)

# THE WHOLE OUTPUT CONTRACT, in one line: two counts. Never a path, never a
# session id, never a byte of any transcript — pointer-only (non-negotiable rule
# 4) is a security property over this input rather than a style one, and
# `tests/transcript-corpus-check.bats` asserts the emitted bytes carry no
# substring of a fixture's content so a later edit cannot relax it.
printf 'transcript-corpus independent=%s min=%s\n' "$independent" "$min"

[[ "$independent" -ge "$min" ]] && exit 0

# The refusal names WHAT WOULD RAISE THE NUMBER, not just the arithmetic. A
# reader told only "0 < 2" has nowhere to go; a reader told which mechanism feeds
# this reading can check whether it ran. The earlier wording said the count could
# never rise, which was the retired rule speaking (see the header) and would send
# a reader to work around a gate rather than to the collector.
echo "::error:: transcript-corpus-check: $independent independent session transcript(s), $min needed. A container reclaim destroys the transcripts it holds (CLOUD-388), so the corpus accumulates only where the collector (CLOUD-651) has run. Check that it is landed and reaching this host before treating a prose corpus as unavailable; a literal derived from one session is fitted to its only example. See mem:prior-art-and-issue-hygiene." >&2
exit 1
