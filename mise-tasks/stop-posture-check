#!/usr/bin/env bash
#MISE description="Gate: an end-of-turn message carrying hedged flag-framing, the one output-posture tell AGENTS.md names literally (reads the message on stdin; pointer-only)"
#
# CLOUD-248. AGENTS.md's output-posture section says the failure it kills is
# "writing findings twice, once durably and once as editorial", names the tell in
# as many words — hedged flag-framing, with two literal examples — and then
# concedes that no gate is possible because "hooks see tool calls, not prose".
# That concession is scoped wrong, and CLOUD-200's own body had it right: a
# *PreToolUse* hook sees tool calls, not prose. A `Stop` hook is handed
# `last_assistant_message`, the text of the turn's final response, so the prose
# does pass through a tool boundary after all — just a different one.
#
# So this adds no policy. AGENTS.md already enumerates; what it lacked was an
# exit code. The literal set below is the set that file already writes down.
#
# Why an enumeration is honest HERE when AGENTS.md says "it is a predicate, not a
# list". That sentence is about the rule as *feedforward*: a list in prose invites
# satisfying the list and drifting elsewhere, which is why the previous version
# did not hold. As a *gate* the tradeoff inverts — an incomplete literal set costs
# recall, never precision, and a true positive stays true. Measured over a real
# 33-turn session transcript this fired 3 times with 3 true positives, and one of
# them is witnessed independently rather than by opinion: that turn's flag-framed
# defect was filed nine turns later, so the kick would have closed a nine-turn
# latency. Recall is the weak half and is stated rather than hidden: of the three
# findings whose staleness a later filing witnesses, this catches one, because
# `last_assistant_message` carries only the FINAL text block — measured at 26,893
# of 60,916 assistant-prose characters, 44%, and two misses sat in earlier blocks.
#
# What was measured and deliberately NOT shipped, so nobody re-derives it:
#   - uncommitted / untracked / unpushed at stop. Already enforced one tier up by
#     the launcher's own Stop hook (~/.claude/stop-hook-git-check.sh, wired in
#     ~/.claude/launcher-settings.json). Duplicating it buys nothing.
#   - "green"/"landed" claims joined against a receipt or `git merge-base`. The
#     claim is about a past SHA while the world-state half tests current HEAD, so
#     the conjuncts are about different objects: 0 true positives, 2 false.
#   - deferral-of-a-settled-call. Fired on a turn that deferred two genuinely
#     ambiguous calls AGENTS.md sanctions deferring, and missed a plainer one.
#   - finding-shape without a durable write (this issue's own conjunct). 1/1 true,
#     but it needs the turn's tool-use records, so it must read the transcript —
#     which lags the current turn's most recent messages, meaning a late
#     `save_issue` reads as "no durable write" and would kick a turn that DID
#     file. Report-only until that ordering is settled; it stays CLOUD-248's.
#
# Pointer-only (non-negotiable rule 4), and here that is load-bearing rather than
# ceremonial: the input is a whole assistant message. The report emits the rule
# id, a count, and the matched literal — a parameter of the rule, defined in this
# file — and never a byte of the surrounding sentence.
#
# Exit 0 clean, 1 the predicate fired (reason on stdout), 2 stdin unreadable.
set -euo pipefail

msg=$(cat) || exit 2
[ -n "$msg" ] || exit 0

# A message QUOTING the tell is not the message MAKING it, and this is not a
# hypothetical distinction: the sibling `run-shape-guard` denied the very command
# that documented it, twice, before its scrubber covered quoted spans. Code spans,
# fenced blocks, block quotes and double-quoted spans all come out first.
#
# WHOLE-INPUT throughout, because the default line-at-a-time model leaves the
# interior of a wrapped quotation exposed and every one of these spans is
# routinely line-wrapped in real prose — the same defect `run-shape-guard` fixed
# at its own scrubber. The last substitution needs it twice over: it matches `\n`
# inside the pattern space, which a line-based reader never has.
#
# `perl -0777` and not sed's NUL-separated mode (CLOUD-282): `-z` is a GNU
# extension, BSD sed exits `illegal option -- z`, and these are GATES — a macOS
# checkout could not run them at all. Byte-identical for all four substitutions,
# differentially verified against the real bats fixtures and both edges (a
# leading `\n`, a blank line before `>`); only `\1` becomes `$1`. Not awk:
# `awk-regex-check` forbids `-v`-passed regexes, and this repo's dev boxes are
# mawk against a gawk runner. The banned literal is deliberately not spelled
# here — `no-gnu-sed-z` in batten.toml is a substring rule over this directory.
scrubbed=$(
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	printf '%s' "$msg" |
		perl -0777 -pe 's/```[^`]*```/FENCED/g' |
		perl -0777 -pe 's/`[^`]*`/CODE/g' |
		perl -0777 -pe 's/"[^"]*"/QUOTED/g' |
		perl -0777 -pe 's/(^|\n)[[:space:]]*>[^\n]*/$1QUOTED/g'
)

# The literal set is AGENTS.md's own two examples plus their direct inflections.
# Kept deliberately narrow: every entry names an act of flagging rather than any
# use of "note" or "flag", so "I noted the exit code" and "the --flag argument"
# are outside it. Inline in the grep, never through `awk -v` (awk-regex-check).
#
# Both the contracted and the expanded auxiliary, because the first draft carried
# only `I'?d` and its own test caught the miss: "one thing I would flag" is the
# commoner spelling of the phrase AGENTS.md writes contracted. Both apostrophes
# too — a straight one and a typographic one are the same word to a reader.
#
# ONE VERB SET ACROSS THE `worth`/`bears` OPENERS (CLOUD-387), because they used to
# carry two and the difference was an accident of how the alternation was written:
# `worth (noting|flagging)` beside `bears (noting|mentioning)`, so `mentioning` was
# a flagging verb to this file under one opener and unknown under the other.
# Measured before and after, one sentence per row:
#
#                        before   after
#   worth noting           fires   fires
#   worth flagging         fires   fires
#   bears noting           fires   fires
#   bears mentioning       fires   fires
#   worth naming          SILENT   fires   <- the witnessed miss
#   worth mentioning      SILENT   fires   <- the asymmetry
#   bears naming          SILENT   fires
#   it's worth naming     SILENT   fires
#   worth calling out     SILENT  SILENT   <- deliberately still out
#
# `naming` is the witnessed one. The CLOUD-347..356 audit closed its report with
# "One open thread worth naming: the census … never interrogated host settings",
# a real finding that reached chat and nothing else and became CLOUD-380 only
# because a human asked. That sentence is silent here; the same sentence with
# `noting` fires. And nothing else covered it: `stop-guard` consults
# `finding-sink-check` precisely WHEN this rule is silent, and that gate needs a
# `path:line` citation the sentence does not carry — so the turn's one advisory
# slot was not spent, it was never claimed.
#
# `calling out` is the line between completing an inflection and inventing a
# phrase list, and it stays out: unwitnessed, and not already in this file. That
# distinction is the whole reason this is not the unmeasured-literal mistake
# CLOUD-323 and CLOUD-326 forbid — those govern a NEW SHAPE, while every verb
# here is either witnessed or already present, inside a construction measured at
# 3/3. Precision holds by construction: "worth naming" is the same
# opener-plus-communication-verb form as "worth noting".
#
# The `I would flag` / `I should note` family keeps `(flag|note)`, measured and
# deliberately unchanged — "I would name that" is not natural flagging, and
# widening there would be the invention this paragraph exists to refuse.
FLAG_VERB="noting|flagging|mentioning|naming"
HEDGES="worth ($FLAG_VERB)|one thing (I would|I['’]?d) (flag|note)|I['’]?d (flag|note) (that|one)|I would (flag|note) that|I should (note|flag)|(it|that)['’]?s worth ($FLAG_VERB)|bears ($FLAG_VERB)"

# `-o` on a here-string, never `producer | grep -q`: under pipefail an
# early-exiting grep in a pipeline promotes a MATCH to a failure status
# (pipefail-grep-check). A here-string has no upstream process to signal.
#
# The count is over MATCHES, not matching lines — `grep -c` answers the second
# question and its own test caught that too: two tells in one sentence counted as
# one, which understates exactly the double-write this rule exists to name.
matches=$(grep -oiE "$HEDGES" <<<"$scrubbed" || true)
[ -n "$matches" ] || exit 0
hits=$(wc -l <<<"$matches" | tr -d ' ')

matched=$(sort -u <<<"$matches" | tr '\n' '|')

cat <<REASON
hedged-flag-framing ${hits} (${matched%|})

AGENTS.md's output posture: a finding's home is an issue or a memory, and chat
stores nothing — so a hedged flag is a finding being written as editorial instead
of durably. This message carries that literal. Either the thing being flagged is
real, in which case it belongs in a \`CLOUD-*\` issue or a memory before the turn
ends (search for an existing home and append; file only if none exists), or it is
not a finding and the hedge should go.

Land it, then say so plainly. If neither applies, set BATTEN_STOP_GUARD_BYPASS=1.
REASON
exit 1
