#!/usr/bin/env bash
#MISE description="Gate: the issue you are about to pull is actually unclaimed (reads get_issue payloads on stdin)"
#
# CLOUD-230. The board's Todo -> In Progress transition is **publish-side only**.
# Measured here on 2026-08-08: a commit carrying `Refs: CLOUD-37`, pushed at
# 04:33:18, moved nothing; the issue went In Progress at 04:35:08, eight seconds
# after `gh pr create` and ~105 seconds after that push. It was Done at 04:38:27.
# So the automation issues a *receipt* for work already written, and structurally
# cannot act as a claim: at pull time nothing has been pushed, so no key can
# travel and there is nothing for the integration to key on.
#
# What that costs, measured rather than hypothesised: CLOUD-49 went In Progress
# at 04:29:34, and a second session started writing it roughly six minutes later
# and threw the result away. The board carried the claim the whole time. Nothing
# made that session read it.
#
# This is the read, given an exit code. `graph-check` already answers the same
# question in aggregate — an In Progress issue is excluded from its ready
# frontier by construction — but the frontier is a set, and pulling is a decision
# about one issue. This is that decision, checkable in one call.
#
# Interface, deliberately the same as `graph-check`: **agents fetch, gates
# decide.** No tracker credential exists, so the caller pipes the
# `get_issue(includeRelations: true)` payload for the issue it means to pull and
# this stays a pure function of stdin — no network, and therefore nothing that
# can hang, rate-limit, or fail differently in the sandbox than in CI.
#
# The three rules, and why the first is the load-bearing one:
#
#   not-todo   status is not Todo — already In Progress, In Review, or Done.
#   assigned   Todo, but someone has already put their name on it.
#   has-pr     a GitHub pull request is already attached to it.
#
# `assigned` deliberately does NOT say "assigned to someone else", because in
# this workspace it cannot: every agent authenticates as the same tracker user,
# so self and other are indistinguishable in the payload. Reporting a name
# comparison here would be a check that looks like it discriminates and does
# not. `not-todo` is what actually catches a concurrent agent, and `has-pr`
# catches one that published before the column moved.
#
# TWO MORE RULES, ANSWERING A DIFFERENT QUESTION (CLOUD-431). All three above
# detect a COMPETITOR, and every one of them reads "clear" when nobody else is
# involved — so they are blind by construction to a SOLE agent moving too fast.
# Measured on CLOUD-427, 2026-08-12: an agent asked to discuss a design instead
# filed the issue, wrote its own Ready block, moved it Todo, piped a payload it
# had hand-written to this gate, took the receipt, and implemented ~600 lines
# across a new module and two new workspace dependencies. Every guard that fired
# gated the SHAPE of an action; none gated the SEQUENCE, and against a
# self-minted receipt "the gates are your authorization" resolves to "I
# authorized myself".
#
#   not-ready              the payload's Ready block fails `ready-lint`, so the
#                          receipt would name a story nothing has refined.
#   refined-this-session   the body changed since this clone recorded reading it
#                          (`issue-read-check`'s baseline). Refinement must
#                          PREDATE the session that implements it.
#   no-read-receipt        there is no baseline to compare against, inside a
#                          clone where there could be (CLOUD-820).
#
# WHY THE BASELINE IS THE FORGERY-RESISTANT HALF. The payload is agent-supplied,
# so any CONTENT claim in it can be authored by the thing being checked —
# `not-ready` alone would be a gate an agent satisfies by writing better prose.
# The baseline is different in kind: it is a hash this clone wrote down BEFORE
# the body could be rewritten, and it lives under `.git/`, so a restart cannot
# reset it. A hand-edited payload defeats it, and that is fabrication rather than
# honest error — outside the threat model, and recorded in the issue's own
# history on the tracker regardless.
#
# AND ABSENCE IS NOT AN ANSWER (CLOUD-820). The baseline can be DELETED, by an
# agent's own clone, with no bypass and no record — and until this row it fell
# through to the `updatedAt`-versus-stamp clock that CLOUD-597 and CLOUD-615 each
# proved wrong in one direction. So the strong half was opt-out. It is a refusal
# now, which is the posture this file already takes three rules down for the
# session stamp; the fallback is DELETED rather than left as dead code, because
# leaving it invites a future reader to restore it as the "lenient" branch.
#
# THE LEGITIMATE PATH MUST NOT PROMPT. Pulling a human-refined issue off the
# frontier and carrying it to landed without asking permission between steps is
# what AGENTS.md's autonomous-workflow section protects, and both rules are
# silent on it: the block passed lint, and it was written in an earlier session.
# In-session refinement stays reachable, but through `BATTEN_CLAIM_CHECK_BYPASS`,
# which makes it a human's visible decision rather than an agent's silent one.
#
# Exit 0 pullable / 1 not pullable / 2 unreadable stdin — matching `graph-check`
# so the two compose in one pipeline.
#
# A SIXTH PATH, WHICH IS NOT A RULE: the deliberate takeover. The three
# competitor rules read a RESUMED branch exactly as they read a collision, and
# they are right about the facts every time — work in flight is In Progress,
# assigned, and carries its own pull request. Measured on this gate's own
# landing: the receipt lives under `.git/` and never leaves the clone, which is
# what makes it unforgeable and also what strands it, so a branch picked up in a
# fresh container can never mint one and can never pass the `verify` half this
# same change adds. In a fleet of disposable containers that is the second
# session on any branch, not an edge case. `BATTEN_CLAIM_TAKEOVER=1` mints over
# the refusals and RECORDS which ones it overrode; it is not folded into
# `BATTEN_CLAIM_CHECK_BYPASS`, because "this story was refined in my session" and
# "I am resuming work that already looks occupied" are different decisions.
#
# The mutation drops the body comparison, which is the path that answers now
# (CLOUD-615): a Ready block this clone wrote then reads as untouched, which is
# the incident laundered through a container restart.
#MUTANT claim-ignores-the-body|s/\[ "\$now_hash" != "\$baseline" \]/false/|CLOUD-615 REPLAY: a body rewritten under this clone is refused even when the stamp is NEWER
# And the mutation that restores what CLOUD-820 deleted: read an ABSENT baseline
# as "nothing to compare, carry on" rather than as a refusal, which is the
# opt-out this row closed — three ordinary steps, none a bypass, none reported.
#MUTANT absent-baseline-is-a-pass|s@^\t\treport_sequence "\$id" "no-read-receipt.*@\t\t:@|A DELETED READ RECEIPT IS A REFUSAL, never a fall-through to the clock
# The takeover must stay OPT-IN. Unset, the refusal is the answer; a mutation that
# takes over unconditionally turns every collision into a silent claim, which is
# the failure this gate exists to prevent.
#MUTANT takeover-always-on|s/^\tif \[ "\$takeover_requested" -eq 1 \]; then$/\tif true; then/|an occupied issue is refused when no takeover is asked for
# And it must RECORD what it overrode: a takeover that mints a receipt
# indistinguishable from a clean pull is a bypass wearing a better name.
# CLOUD-520. Neutering the liveness filter restores the old behaviour — every
# attached PR refuses, merged or not — so the case that proves a merged
# predecessor is pullable must go RED. Without this row the narrowing is a
# change nothing shows can fail, which is exactly what shipped unproven before.
#MUTANT has-pr-ignores-liveness|s/(\$s != "merged" and \$s != "closed")/(true)/|CLOUD-520 clause a — a MERGED pull request is a predecessor, not a competitor
#MUTANT takeover-unrecorded|s/^\t\tif \[ "\$takeover" -ne 0 \]; then$/\t\tif false; then/|NAMES the refusals it overrode
# And it must record the BASE it was claimed against (CLOUD-516). Drop that one
# line and the receipt goes back to being a bare file whose existence
# authorises every edit — which is how a claim naming CLOUD-230 sat on a
# restarted branch through four unrelated stories, reporting nothing.
# CLOUD-733's two. The first drops the "does the recorded branch still exist"
# test, so ANY receipt becomes adoptable — including a live branch's, which turns
# a recovery into a way to steal another branch's claim.
#MUTANT adopt-ignores-liveness|s/^\t\tgit show-ref --verify --quiet "refs\/heads\/\$recorded" && continue$/\t\t:/|a receipt whose branch still exists is not adopted
# The second drops the guard against adopting over an existing receipt, which
# would let an adoption discard the claim this branch already holds.
#MUTANT adopt-over-a-live-claim|s/^\tif \[ -e "\$dest" \]; then$/\tif false; then/|adopting onto a branch that already has a receipt is refused
#MUTANT claim-records-no-base|s/^\t\techo "base .*$/\t\t:/|the receipt records the origin/main it was claimed against
# CLOUD-526's projection is only real if the three body-free rules can actually
# ANSWER without a body. Drop the short-circuit and an already-refused issue
# falls into `ready-lint`, which cannot read a bodyless payload and exits 2 — so
# the refusal it had already earned is replaced by "could not look".
#MUTANT projection-loses-the-cheap-refusals|s/^\tif \[ "\$blocked" -ne "\$refused_before" \]; then$/\tif false; then/|reachable on a payload with no description
set -euo pipefail

# --- arguments (CLOUD-733) ---------------------------------------------------
#
# This task parsed NO arguments until now, so the loop is new and it takes a
# documented hazard with it: `shift 2` on a single remaining argument shifts
# nothing and returns non-zero. `errexit` IS on here, unlike `mcp-timeout-budget`
# where the same shape span the loop forever — but relying on that would make the
# arity of every future flag depend on a `set` line at the top of the file, so
# each one checks explicitly and `tests/claim-check.bats` asserts it under
# `timeout`. A gate that hangs never reports, and both `verify` and the hk gate
# wait on this one.
#
# `--adopt` takes NO value and `--adopt-from` takes one, rather than a single
# flag with an optional argument. An optional-value flag cannot tell
# `--adopt --takeover` from `--adopt <name>` without a rule about which tokens
# look like names, and a rule about rules is what this repo's config posture
# refuses.
adopt=0
adopt_from=""
takeover_flag=0
while [ $# -gt 0 ]; do
	case "$1" in
	--adopt)
		adopt=1
		shift
		;;
	--adopt-from)
		if [ $# -lt 2 ] || [ -z "$2" ]; then
			echo "::error:: claim-check: --adopt-from needs the branch name the receipt was minted under" >&2
			exit 2
		fi
		adopt=1
		adopt_from="$2"
		shift 2
		;;
	# The flag half of `BATTEN_CLAIM_TAKEOVER` (CLOUD-729). The env var is kept
	# and unchanged; what this adds is REACHABILITY. A refusal naming a remedy
	# its reader cannot execute is not a remedy, and an agent under a permission
	# classifier that reads `FOO=1 cmd` as a bypass has no way to run the
	# documented one.
	--takeover)
		takeover_flag=1
		shift
		;;
	*)
		echo "usage: claim-check [--adopt | --adopt-from <branch>] [--takeover]  (get_issue payloads on stdin)" >&2
		exit 2
		;;
	esac
done

# The one escape hatch, and it is deliberately not shared with the mediated
# gate's (`batten hook`'s own). That one says "do not refuse my edit"; this one
# says "mint a receipt for a story refined in this session". They are different
# decisions and a single switch for both would grant the second while a human
# only meant the first. A gate with false positives gets bypassed, and a bypassed
# gate enforces nothing — so the hatch exists, and it is loud rather than silent.
if [ -n "${BATTEN_CLAIM_CHECK_BYPASS:-}" ]; then
	echo "claim-check: BATTEN_CLAIM_CHECK_BYPASS set — the refinement-sequence rules are not being applied" >&2
fi

# The two spellings of ONE decision (CLOUD-729), resolved here rather than at the
# use site. Not a style choice: `|` is the `#MUTANT` field delimiter, so a
# condition containing `||` cannot be expressed as a mutation, and the row that
# keeps the takeover opt-in is one this gate must not lose.
takeover_requested=0
if [ -n "${BATTEN_CLAIM_TAKEOVER:-}" ] || [ "$takeover_flag" -eq 1 ]; then
	takeover_requested=1
fi

# --- adoption: re-key a stranded receipt (CLOUD-733) -------------------------
#
# A branch NAME outlives nothing, but the receipt keyed by it does: `git branch
# -m` destroys the old ref and leaves `claim.<old-name>` on disk, describing this
# exact work and unreachable by every reader. Measured on CLOUD-730, where it
# cost a closed pull request to recover by hand.
#
# WHY THIS IS ON THE MINT SIDE, AND WHY THAT IS THE WHOLE DESIGN. The obvious fix
# is a reader that notices the stray and adopts it. It cannot work: the mediated
# `claim-needs-receipt` row fires on the FIRST WRITE, before the branch carries a
# commit, so the only thing that could corroborate the claim — the issue keys the
# branch's own commits name — does not exist yet. A reader left to infer from the
# receipt alone would adopt a stray from a DELETED branch as readily as one from a
# rename, which is a gate weakening itself on a guess. So the author asserts it,
# once, and the assertion is recorded. The readers are untouched.
#
# The first version of this issue specified the reader form and was inert: it
# asked for "a receipt whose recorded branch differs from its filename", and
# after a rename those two AGREE — both name the old branch. Recorded here
# because the mistake is easy to make twice.
#
# ORPHAN, not "any other receipt": a receipt whose recorded `branch` no longer
# resolves as a ref. A rename destroys exactly one ref, so it produces exactly
# one orphan, and a receipt belonging to a branch that still exists is that
# branch's, not a stray.
adopt_receipt() {
	local git_dir branch dest candidates=() file recorded old
	git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
		echo "::error:: claim-check: --adopt needs a git checkout" >&2
		return 2
	}
	branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || branch=""
	if [ -z "$branch" ]; then
		echo "::error:: claim-check: --adopt needs a branch; HEAD is detached, and a detached HEAD has no name to key a claim on" >&2
		return 2
	fi
	dest="$git_dir/batten-receipts/claim.${branch//\//-}"
	if [ -e "$dest" ]; then
		echo "::error:: claim-check: this branch already carries a claim receipt; adopting over it would discard the claim it records" >&2
		echo "  branch $branch" >&2
		return 1
	fi

	for file in "$git_dir"/batten-receipts/claim.*; do
		[ -f "$file" ] || continue
		# Read by KEY, never by line number: line 1 is the id list every existing
		# reader parses, and the `branch` line is emitted with the others below.
		recorded=$(awk '/^branch /{print substr($0, 8); exit}' "$file" 2>/dev/null) || recorded=""
		# A receipt predating this change records no branch, and is NOT adoptable.
		# Reading "no branch line" as "adopt me" would grandfather in every receipt
		# ever written, which is the direction that turns a recovery into a bypass.
		[ -n "$recorded" ] || continue
		# Still a live branch: this receipt is that branch's, not a stray.
		git show-ref --verify --quiet "refs/heads/$recorded" && continue
		[ -z "$adopt_from" ] || [ "$adopt_from" = "$recorded" ] || continue
		candidates+=("$file")
	done

	if [ "${#candidates[@]}" -eq 0 ]; then
		echo "::error:: claim-check: no orphaned claim receipt to adopt — every receipt here names a branch that still exists, or records no branch at all" >&2
		return 1
	fi
	if [ "${#candidates[@]}" -gt 1 ]; then
		echo "::error:: claim-check: more than one orphaned receipt; name the one this branch continues with --adopt-from" >&2
		for file in "${candidates[@]}"; do
			echo "  $(awk '/^branch /{print substr($0, 8); exit}' "$file")" >&2
		done
		return 1
	fi

	old=$(awk '/^branch /{print substr($0, 8); exit}' "${candidates[0]}")
	# RECORDED, never silent. A recovery indistinguishable from a clean pull is a
	# bypass wearing a better name — the same reason the takeover names the
	# refusals it overrode. The `branch` line is rewritten to this branch so the
	# receipt keeps describing where it lives, and `adopted-from` keeps where it
	# came from.
	{
		grep -v '^branch ' "${candidates[0]}"
		echo "branch $branch"
		echo "adopted-from $old"
	} >"$dest"
	rm -f "${candidates[0]}"
	echo "claim-check: adopted the claim receipt from \"$old\" onto \"$branch\", recorded in the receipt"
	return 0
}

if [ "$adopt" -eq 1 ]; then
	# No payload is read: adoption re-keys a claim that was already checked when
	# it was minted. Asking for stdin here would invite a caller to re-assert a
	# verdict this gate is not re-taking.
	adopt_receipt
	exit $?
fi

# Accept either a JSON array or a concatenated stream of payload objects, the
# same normalisation `graph-check` performs, so a caller can pipe either shape
# to either gate. Exit 2 is "unreadable input", distinct from a failing check.
#
# `description` joined `id` and `status` with CLOUD-431 and LEAVES AGAIN WITH
# CLOUD-526, and the reason it can leave is that its argument was never about the
# contract. That argument — "a rule that silently disappears when a field is
# absent is a rule an agent turns off by sending less" — forbids SKIPPING a rule
# on a thin payload. It does not oblige every rule to demand the largest field on
# the row. Three of this gate's four rules decide from `status`, `assignee` and
# `attachments` and never look at the body; only `not-ready` reads it, and that
# one demands it at its own site below, by name, as a refusal.
#
# So the entry contract is what EVERY issue needs: `id` and `status`.
# `updatedAt` is no longer read by any RULE — CLOUD-820 deleted the clock arm —
# and survives only as a line in the receipt, where it is recorded rather than
# decided on, so its absence is written as `-` and never refuses.
#
# `assignee` is deliberately NOT required, and this is a fact about the tracker
# rather than a softening: Linear omits the key entirely for an unassigned issue,
# so `has("assignee")` would refuse the very payloads the `assigned` rule exists
# to pass. Absent means unassigned, which is what the rule already reads it as.
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' 2>/dev/null) ||
	[ "$(jq 'length' <<<"$issues")" = 0 ] ||
	! jq -e 'all(.[]; has("id") and has("status"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: stdin is not a set of get_issue payloads (need id and status per issue)" >&2
	exit 2
fi

blocked=0
# What the takeover overrode, accumulated as `<id> <rule>` pairs so the receipt
# can name them rather than merely admitting that something was overridden.
overridden=""
takeover=0
# Pointer-only per non-negotiable rule 4: the issue id and the rule id, plus the
# PR number where there is one. Never an issue body, never a title.
report() {
	echo "$1 $2" >&2
	blocked=$((blocked + 1))
	overridden="${overridden}${overridden:+; }$1 $2"
}

# THE SECOND COUNTER, AND WHY IT IS SEPARATE (CLOUD-816). `report` above feeds
# the counter the takeover zeroes, and the four refinement-sequence rules used
# it too — so `--takeover`, documented for "the competitor is this branch",
# also cleared `refined-this-session`, which is the whole of CLOUD-431.
# Measured on a payload with NO competitor at all (Todo, unassigned, no
# attachments): without the flag the gate refused on the sequence rule; with it
# the gate exited 0 and minted a receipt. The header below states these are two
# decisions; this is what makes the code say so.
#
# The projection short-circuit at `refused_before` still reads `blocked` alone,
# which is correct: it asks "did a COMPETITOR rule fire for this issue", and the
# body-reading arms below it are exactly the ones this counter serves.
sequence_blocked=0
report_sequence() {
	echo "$1 $2" >&2
	sequence_blocked=$((sequence_blocked + 1))
}

# --- the refinement-sequence machinery (CLOUD-431) ---------------------------

# The session boundary. Written by `.claude/hooks/session-start.sh` before it
# does anything else, so its mtime is when the session BEGAN.
#
# Two sessions sharing one clone read the LATER stamp, which is stricter and
# never laxer: the failure direction is a refusal, not a pass.
stamp_file=""
if stamp_dir=$(git rev-parse --git-dir 2>/dev/null); then
	stamp_file="$stamp_dir/batten-receipts/session-start"
fi

lint="$(dirname -- "${BASH_SOURCE[0]}")/ready-lint.sh"

while read -r id; do
	[ -n "$id" ] || continue
	payload=$(jq -c --arg id "$id" '.[] | select(.id == $id)' <<<"$issues")
	status=$(jq -r '.status // ""' <<<"$payload")
	# Where this issue's own refusals start, so the body-reading arm below can
	# tell "nothing has objected yet" from "the cheap rules already answered"
	# (CLOUD-526). `blocked` is cumulative across the set; the delta is per issue.
	refused_before=$blocked

	if [ "$status" != "Todo" ]; then
		report "$id" "not-todo (in $status)"
		continue
	fi

	# `assignee` is a name string when set and absent or null when not.
	if [ "$(jq -r 'if (.assignee // null) == null then "" else "set" end' <<<"$payload")" = "set" ]; then
		report "$id" "assigned"
	fi

	# An attachment whose URL is a GitHub pull request. Matched on the URL shape
	# rather than the title, which is free text a human wrote.
	#
	# LIVE, NOT MERELY PRESENT (CLOUD-520). This rule's purpose is narrower than
	# what it used to implement: the header says it "catches one that published
	# before the column moved", which is a claim about an OPEN pull request. A
	# MERGED one is the opposite signal — evidence that work finished, not that
	# it is in flight — and refusing on it makes an issue released back to Todo
	# permanently unpullable. Measured on CLOUD-479: `Todo`, unassigned, its own
	# body inviting the next taker, refused on PR #376 which had merged the day
	# before.
	#
	# THE STATE COMES FROM THE CALLER, and that is forced rather than chosen.
	# This gate is a pure function of stdin — no tracker credential, no network,
	# so it cannot hang or rate-limit and its suite runs unconditionally — and
	# the tracker's attachment objects carry `id`, `title`, `subtitle` and `url`
	# and no state at all (measured 2026-08-19). So the fix cannot be a lookup
	# here; it is the shape `claimed-keys` already uses, where the caller supplies
	# the facts about a PR this checkout did not author.
	#
	# ABSENT REFUSES, and that default is load-bearing. A caller that supplies
	# nothing gets exactly today's behaviour, so this narrowing can only ever turn
	# a false refusal into a pull — never a real competitor into a silent pass.
	# Open refuses, malformed refuses (a parse failure must not become a pass),
	# and only an explicit merged/closed reading stands down.
	pr=$(jq -r '[.attachments // [] | .[]
	             | select(.url? and (.url | test("github\\.com/.+/pull/[0-9]+")))
	             | select(((.state // "") | ascii_downcase) as $s
	                      | ($s != "merged" and $s != "closed")
	                        and ((.merged // false) != true))
	             | .url]
	            | first // ""' <<<"$payload")
	if [ -n "$pr" ]; then
		report "$id" "has-pr (${pr##*/}) — if it is merged or closed, say so on the attachment (\"state\": \"merged\") and re-run"
	fi

	# --- is this a real, refined story? (CLOUD-431) --------------------------
	#
	# Skipped wholesale under the bypass, announced above. Both rules below are
	# about the SEQUENCE of refinement, and the bypass is the one way a human
	# says "I refined it just now, on purpose".
	[ -n "${BATTEN_CLAIM_CHECK_BYPASS:-}" ] && continue

	# THE BODY IS NEEDED FROM HERE DOWN, AND ONLY FROM HERE DOWN (CLOUD-526).
	# `not-todo`, `assigned` and `has-pr` have all had their say; if any of them
	# refused, this issue is not pullable and no reading of the body can make it
	# so. Returning that answer on a payload that carries no body is the point of
	# the projection — those three are the common refusals, and they were costing
	# a full re-typed description to reach.
	#
	# It also keeps them REACHABLE. Without this, an assigned issue sent without a
	# body would fall into `ready-lint`, exit 2 as unreadable, and the `assigned`
	# refusal it had already earned would be lost behind "could not look".
	if [ "$blocked" -ne "$refused_before" ]; then
		continue
	fi

	# Nothing has objected yet, so the block decides — and now the body is a
	# declared requirement of THIS arm rather than of the gate. Refused by name:
	# `ready-lint` would also exit 2 on a bodyless payload, but as "not a
	# get_issue payload", which sends the reader to the wrong question.
	if ! jq -e 'has("description") and (.description != null)' <<<"$payload" >/dev/null 2>&1; then
		echo "::error:: claim-check: $id carries no description, and nothing else has refused it — the not-ready rule decides on the body. Re-fetch this one issue with get_issue and pipe it again." >&2
		exit 2
	fi

	# `not-ready`. The same gate `graph-check` already calls by path, at the
	# point of PULLING — which is where the decision is actually made, and what
	# makes a claim receipt mean what its name implies.
	#
	# `.description` is asserted immediately above, so the only exit-2 left here
	# is `ready-lint` failing to read what it was handed — "could not look" in
	# both scripts, and never a verdict.
	lint_rc=0
	printf '%s' "$payload" | "$lint" >/dev/null 2>&1 || lint_rc=$?
	if [ "$lint_rc" = 2 ]; then
		echo "::error:: claim-check: ready-lint could not read $id's payload at all" >&2
		exit 2
	fi
	if [ "$lint_rc" != 0 ]; then
		report_sequence "$id" "not-ready (ready-lint refuses this block — run \`mise run ready-lint\` on it)"
		continue
	fi

	# `refined-this-session`. The sequence predicate, and the forgery-resistant
	# one: the baseline is a hash this clone wrote down before the body could move.
	#
	# OUTSIDE A CHECKOUT the question is not applicable rather than unanswerable,
	# and skipping it there closes no hole: the receipt is a side effect of being
	# in a clone, so a run from anywhere else mints nothing for the mediated gate or
	# `verify` to honour. Refusing here would only break the composability
	# `graph-check` and this gate share — a caller inspecting the board from
	# anywhere still deserves the verdict.
	if [ -z "$stamp_file" ]; then
		continue
	fi
	# INSIDE one, a MISSING stamp is a REFUSAL, not a pass. The sequence question
	# is answerable here and we simply cannot see the answer, and a gate that
	# silently clears everything it cannot see is the false green this repo keeps
	# re-meeting. The remedy is local and cheap — the SessionStart hook writes it
	# before it does anything else — and the bypass covers a human who means it.
	if [ ! -e "$stamp_file" ]; then
		report_sequence "$id" "no-session-stamp (run .claude/hooks/session-start.sh, or set BATTEN_CLAIM_CHECK_BYPASS)"
		continue
	fi
	# THE BODY BASELINE, AND NOTHING ELSE (CLOUD-597, CLOUD-615, CLOUD-820).
	# `issue-read-check` records a hash of the body when this clone reads an
	# issue, and `issue-read-guard` will not let a `save_issue` through without
	# that receipt — so refining an issue always lays down what it looked like
	# beforehand. Comparing the body now against that baseline asks the question
	# this rule is named for: did the body change UNDER THIS CLONE. A reciprocal
	# relation, a label or a bulk board touch does not move it; writing a Ready
	# block does.
	#
	# It REPLACED the clock pair rather than supplementing it, because both clocks
	# were wrong in opposite directions and each hid the other: `updatedAt` moves
	# on any write to the row, so the rule refused claims nobody had refined
	# (CLOUD-597), and the stamp is truncated on every SessionStart, so a
	# container restart laundered a self-refinement into a pass (CLOUD-615). The
	# baseline lives under `.git/`, so a restart cannot reset it.
	#
	# AND UNTIL CLOUD-820 THE REPLACEMENT WAS OPT-OUT. The baseline cannot be
	# reset; it can be DELETED, and an absent one fell through to exactly the
	# comparison it replaced. Three ordinary steps, none a bypass and none
	# reported: refine the issue, remove `issue-read.<KEY>` from your own clone,
	# wait for a SessionStart to move the stamp past the refinement. Worse than a
	# hatch, because it needs no attacker — the receipt was deleted for a
	# legitimate reason (CLOUD-691's hollow-digest class) and the honest repair of
	# one defect silently disarmed this gate.
	#
	# So absence is a REFUSAL, which is the posture the stamp arm above already
	# takes and the words there apply unchanged: the sequence question is
	# answerable inside a clone and we simply cannot see the answer. The remedy is
	# local, cheap and named — one `issue-read-check` over the payload already in
	# hand — and the bypass covers a human who means it.
	#
	# THE HONEST LIMIT, stated here because the next author will otherwise
	# rediscover it by hitting it: a FRESH CLONE has no baseline, and neither had
	# the stamp — an agent that refines in one container and implements in a new
	# clone cannot be told from one that never read the issue. What changed is
	# which way that resolves: it used to be a silent pass, and it is now a
	# refusal an agent clears by taking the read it should have taken anyway.
	# Closing it PROPERLY needs an identity the harness supplies, which does not
	# exist (CLOUD-615's third candidate).
	receipt_dir="$stamp_dir/batten-receipts"
	receipt="$receipt_dir/issue-read.$id"
	baseline=$(awk 'NR==1{print $4}' "$receipt" 2>/dev/null) || baseline=""
	if [ -z "$baseline" ] || [ "$baseline" = "-" ]; then
		# COULD NOT LOOK IS ITS OWN ANSWER, and it must not collapse into either
		# of the other two (CLOUD-251, one more time). A receipt store this
		# process cannot read is not a missing receipt: the file may be there and
		# say the body is unchanged. Exit 2 is this script's channel for that
		# everywhere else, so it is the channel here.
		#
		# A path that EXISTS and is not a readable regular file is the same
		# answer, and it is the one a suite can exercise without depending on
		# whether the runner is root — where `-r` is true whatever the mode bits
		# say, so a permission fixture would assert nothing.
		if [ -e "$receipt" ] && { [ ! -f "$receipt" ] || [ ! -r "$receipt" ]; }; then
			echo "::error:: claim-check: $id's read receipt exists and cannot be read, so the body baseline could not be looked at — this is not the same as having none" >&2
			exit 2
		fi
		if [ -e "$receipt_dir" ] && { [ ! -d "$receipt_dir" ] || [ ! -r "$receipt_dir" ] || [ ! -x "$receipt_dir" ]; }; then
			echo "::error:: claim-check: the receipt store at \$GIT_DIR/batten-receipts cannot be read, so no baseline could be looked at for $id" >&2
			exit 2
		fi
		# A hollow receipt (`body_hash` = `-`, CLOUD-691's class) certifies
		# nothing, so it is absence rather than a weaker yes — the distinction
		# that made this rule opt-out in the first place.
		report_sequence "$id" "no-read-receipt (no body baseline for $id under \$GIT_DIR/batten-receipts — pipe this payload to \`mise run issue-read-check\` first, or set BATTEN_CLAIM_CHECK_BYPASS)"
		continue
	fi
	now_hash=$(jq -r '.description // ""' <<<"$payload" | git hash-object --stdin 2>/dev/null) || now_hash=""
	if [ -z "$now_hash" ]; then
		echo "::error:: claim-check: could not hash $id's body to compare against the read this clone recorded" >&2
		exit 2
	fi
	# NAMES WHICH COMPARISON DECIDED. Two comparisons used to print one rule id
	# and differ only in a parenthetical, which is how a verdict reached by the
	# clock was indistinguishable from one reached by the baseline — and so how
	# the fall-through stayed invisible. There is one comparison now, and it says
	# so.
	if [ "$now_hash" != "$baseline" ]; then
		report_sequence "$id" "refined-this-session (body baseline: the body changed since this clone read it)"
	fi
done <<<"$(jq -r '.[].id' <<<"$issues")"

if [ "$blocked" -ne 0 ]; then
	# THE DELIBERATE TAKEOVER, which this message has always named without
	# offering (CLOUD-431). The three competitor rules read a RESUMED branch
	# exactly as they read a collision, and they are right about the facts every
	# time: work in flight IS In Progress, IS assigned, and DOES carry its own
	# pull request. What they cannot see is that the competitor is this branch.
	#
	# MEASURED, on this gate's own landing. The receipt lives under `.git/` and
	# never leaves the clone — which is the property that makes it unforgeable and
	# also the one that strands it. A branch picked up in a fresh container has no
	# receipt, cannot mint one (all three rules fire, truthfully), and so can never
	# pass the `verify` half this same change adds. In a fleet where a container is
	# disposable that is not an edge case; it is the second session on any branch.
	#
	# So the hatch is a TAKEOVER rather than a bypass, and the distinction is what
	# it writes down: the receipt records which rules fired and for which ids, so
	# the claim says "I took this over from a state that looked occupied" instead
	# of quietly looking like a clean pull. `BATTEN_CLAIM_CHECK_BYPASS` is not
	# widened to cover this — that switch means "this story was refined in my own
	# session", a different decision a human might well want without this one.
	# The flag and the env var are ONE decision with two spellings (CLOUD-729):
	# the env var is unreachable to an agent whose harness classifies `FOO=1 cmd`
	# as a bypass, and a remedy its reader cannot execute is not a remedy. They
	# record the identical line, so a receipt cannot say which was used — that is
	# deliberate, because the decision is what is being recorded, not the syntax.
	if [ "$takeover_requested" -eq 1 ]; then
		echo "claim-check: takeover requested — claiming over $blocked refusal(s) above, recorded in the receipt" >&2
		takeover="$blocked"
		blocked=0
	else
		echo "::error:: claim-check: not pullable — someone is already on it. Pick another issue from \`mise run graph-check\`'s frontier, or take it over deliberately with BATTEN_CLAIM_TAKEOVER=1, which mints the receipt and records what it overrode." >&2
		exit 1
	fi
fi

# THE SEQUENCE RULES SURVIVE THE TAKEOVER (CLOUD-816), and this is the arm that
# makes the header above true rather than merely stated. Checked AFTER the
# takeover arm, deliberately: a resumed branch may legitimately clear all three
# competitor rules and still be refused here, and the reader needs both facts.
#
# The refusal names the OTHER hatch, because offering `--takeover` for this is
# what shipped the hole: a remedy that works for the wrong reason reads as
# permission. `BATTEN_CLAIM_CHECK_BYPASS` means "this story was refined in my
# own session", which is exactly the admission this rule is asking for.
#MUTANT takeover-clears-the-sequence-rules|s/^if \[ "\$sequence_blocked" -ne 0 \]; then$/if false; then/|a sequence refusal is NOT cleared by --takeover
if [ "$sequence_blocked" -ne 0 ]; then
	echo "::error:: claim-check: $sequence_blocked refinement-sequence refusal(s) above, and --takeover does not clear them. That flag answers \"the competitor is this branch\"; these rules answer \"was this story refined before the session implementing it\", which is a different question and the one CLOUD-431 exists to ask. If the honest answer is that you refined it yourself, that decision is BATTEN_CLAIM_CHECK_BYPASS, which says so in the receipt." >&2
	exit 1
fi

# --- the claim receipt (CLOUD-272) -------------------------------------------
#
# This gate used to be a pure read: it answered "is this pullable" and left no
# trace, so nothing downstream could tell a claimed branch from an unclaimed one
# — and the mediated claim gate needs exactly that distinction to sit between
# discovering
# work and editing files for it.
#
# Written ONLY here, on the pullable path, which is what makes it a claim rather
# than a record of an attempt: a `not-todo` / `assigned` / `has-pr` answer mints
# nothing.
#
# Keyed by BRANCH, not by the commit SHA `ready-guard`'s receipts use. That
# receipt should expire on an amend or a rebase, because it attests to a property
# of those exact bytes; a claim attests to a decision about an *issue*, which
# every commit on the branch continues to serve. A SHA-keyed claim would demand a
# re-claim per commit, which is the false-positive rate that gets a guard
# bypassed.
#
# The verdict above does not depend on any of this. Outside a checkout, or with
# an unwritable git dir, the answer still stands and only the side effect is
# skipped — `graph-check` and this compose in one pipeline, and a caller
# inspecting the board from anywhere still deserves the verdict.
if git_dir=$(git rev-parse --git-dir 2>/dev/null) &&
	branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) &&
	[ -n "$branch" ] &&
	mkdir -p "$git_dir/batten-receipts" 2>/dev/null; then
	# Slashes are the one character a filename cannot carry; the substitution
	# must match `receipt::branch_receipt_name`'s spelling exactly, which
	# `receipt::tests::the_branch_receipt_filename_matches_the_minting_task` pins.
	#
	# WIDENED FROM A BARE ID LIST (CLOUD-431) to the record the sequence question
	# needs — the ids, the `ready-lint` verdict at claim time, when the claim was
	# made, and the `updatedAt` the payload reported. The mediated gate reads only the
	# file's EXISTENCE, so nothing downstream breaks on the new lines; they are
	# for the human debugging a refusal, who otherwise has to reconstruct which
	# revision the claimant had in front of them. Line 1 keeps the id list exactly
	# where it was, so any reader that did parse it still finds it.
	#
	# Pointer-only: keys, a verdict word and timestamps. Never a line of the body
	# that was linted.
	{
		jq -r '[.[].id] | join(" ")' <<<"$issues"
		if [ -n "${BATTEN_CLAIM_CHECK_BYPASS:-}" ]; then
			echo "ready-lint bypassed (BATTEN_CLAIM_CHECK_BYPASS)"
		else
			echo "ready-lint pass"
		fi
		# A takeover is recorded with WHAT it overrode, never as a bare flag: the
		# reason to allow one is that a resumed branch looks identical to a
		# collision, and the only thing that tells them apart afterwards is which
		# rules fired for which ids.
		if [ "$takeover" -ne 0 ]; then
			echo "takeover $takeover refusal(s) overridden (BATTEN_CLAIM_TAKEOVER): $overridden"
		fi
		# THE GROOMED WEAKENINGS (CLOUD-789), and this is the line that makes
		# "the decision predates the work" computable rather than asserted.
		#
		# `config-lint` refuses every base-ref weakening and carries no flag that
		# admits one, deliberately (CLOUD-236): a relaxation an author asserts at
		# PR time is a rubber stamp, because this repository reviews AFTER merge.
		# Its header names the only admissible source — the grooming-time record
		# — and this is where that record is captured, at the one moment a gate
		# has the groomed body in front of it and the work has not started.
		#
		# Captured HERE rather than read later for the reason the whole receipt
		# exists: afterwards, nothing recovers what the claimant had in front of
		# them. A body re-read at lint time is a body that may have been rewritten
		# since, and the tracker mints `updatedAt` forward, so the revision this
		# receipt already names is the pin.
		#
		# Pointer-only, as the rest of this file: a smell id and the config key it
		# sits at, never the clause's prose or the reason it gives.
		jq -r '
			.[] as $issue
			| (($issue.description // "") | split("\n")[])
			| select(test("^[[:space:]]*([*-][[:space:]]*)?\\*\\*Weakens:\\*\\*[[:space:]]"))
			| capture("\\*\\*Weakens:\\*\\*[[:space:]]+`(?<smell>[a-z0-9.-]+)`[[:space:]]+at[[:space:]]+`(?<key>[^`]+)`")
			| "weakens \($issue.id) \(.smell) \(.key)"
		' <<<"$issues" 2>/dev/null || true
		echo "claimed-at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		jq -r '[.[] | "updated-at \(.id) \(.updatedAt // "-")"] | .[]' <<<"$issues"
		# THE BASE THIS CLAIM WAS MADE AGAINST (CLOUD-516). A branch NAME outlives
		# the branch it described: `git checkout -B <name> origin/main` is the
		# documented remedy after a PR merges, and it discards the commits that
		# were the branch while this file, keyed by the name, survives. A receipt
		# recording nothing cannot notice, so the guard passed on a claim for an
		# unrelated issue through four stories.
		#
		# Recorded, not derived later: the reader needs what was true AT CLAIM
		# TIME, and no amount of looking at the repository afterwards recovers it.
		# Same shape as `linear-check`'s receipt, which records the `origin/main`
		# it was linear against for the same reason.
		#
		# Emitted last and read by KEY, never by line number, so line 1 stays the
		# id list every existing reader parses. `-` when origin/main does not
		# resolve, which the reader treats as void rather than as agreement: a
		# claim whose base could not be read is exactly as unproven as one that
		# recorded none.
		# `--verify --quiet`, not a bare rev-parse: an unresolvable ref makes
		# rev-parse print the REF ITSELF to stdout before failing, so the
		# fallback would append to it and record a two-line "origin/main\n-".
		# Measured, not guessed.
		echo "base $(git rev-parse --verify --quiet origin/main || echo -)"
		# THE BRANCH THIS WAS MINTED FOR (CLOUD-733), which the FILENAME already
		# encodes — until the branch is renamed, at which point the filename is
		# the only record and it names something that no longer exists. Recorded
		# so `--adopt` can tell a stranded receipt from a live branch's, by asking
		# git whether the recorded name still resolves.
		#
		# Emitted by key like `base`, so line 1 stays the id list.
		echo "branch $branch"
	} >"$git_dir/batten-receipts/claim.${branch//\//-}" 2>/dev/null || true
fi

echo "claim-check: pullable ($(jq 'length' <<<"$issues") issue(s)) — claim it before you write code: move Todo -> In Progress and assign yourself. The tracker automation will not do this for you; it fires on the PR event, which is the end of the work, not the start."
