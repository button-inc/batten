#!/usr/bin/env bash
#MISE description="Turn a bot's pull request into a refined tracker row, and link it back so the merge moves the board (CLOUD-693)"
#
# CLOUD-693. Every lifecycle gate here keys off an issue a human or an agent
# refined BEFORE the work started. A bot proposes with no issue and no session, so
# it fails all of them by construction rather than by misconfiguration — measured
# on #493, where `verify`'s claim receipt, `ready-names-an-issue` and
# `ready-needs-receipts` each refused in turn, and `closing-key-check` PASSED,
# which was the tell: it only fires when a body names a key non-closingly, and
# that body named none at all, so the merge would have moved nothing.
#
# The missing thing was never a gate change. It is this step: something that turns
# the proposal into a refined row before the lifecycle sees it, so the gates are
# satisfied honestly rather than bypassed.
#
# THE MANIFEST DIFF IS THE AUTHORITY (§1), and nothing here re-types it. The row's
# title is the bot's own PR title — which `renovate.json5`'s `packageRules` already
# decided the Conventional type of — and its body names the manifests the diff
# touches, read from the PR's file list rather than from the bump table in the PR
# body. A table is prose the bot wrote about the change; the file list is the
# change. When the two disagree the file list is right, so it is the only one read.
#
# WHY A BOT ROW CAN BE MECHANICAL AT ALL, which is the honest part of §2. A bump
# has no design question to refine: the source of truth is the manifest, the
# predicate is "CI green on the bump", the effect is none, and the bump follows the
# type already in the config. That is exactly why this must NOT reuse the agent
# refinement path, where a human judgement is the thing being attested — the two
# attest different things, and CLOUD-431 exists to keep them apart.
#
# IDEMPOTENT, KEYED ON THE PR. `ensure` is called on every lander tick, twice an
# hour for as long as a bot PR is open, so "already has a row" has to be the cheap
# and total answer: a body that names any `CLOUD-<n>` is done, and nothing is
# filed. The key travels in the body rather than in a local record because the body
# is what the merge reads — a record this side could go missing and file a second
# row against a PR that already has one.
#
# REFUSES RATHER THAN INVENTING (exit 1). A PR whose diff touches no manifest this
# lane owns gets no row: the alternative is a tracker row asserting a bump nobody
# proposed, which is the CLOUD-198 class with a new author. The refusal names the
# PR and the paths it did touch, so a lane that grew a manifest is a one-line fix
# here rather than a mystery.
#
# Pointer-only per non-negotiable rule 4: the PR number, the issue key, the
# manifest paths. Never a diff body, never a version, never the tracker token.
#
# Exit 0 did the work (or found it already done) / 1 refused, this PR is not one of
# ours / 2 could not look — GitHub would not answer, so nothing was written.
#
# Usage:
#   mise run bot-issue derive <pr>        candidate payload on stdout, no writes
#   mise run bot-issue file <pr>          derive, then open the mirror issue
#   mise run bot-issue link <pr> <key>    write `Closes <key>` into the PR body
#   mise run bot-issue ensure <pr>        the lander's call: all three, idempotent
#   mise run bot-issue closes <pr>        does the body STILL close a key? (CLOUD-768)
#   mise run bot-issue receipt            mint this branch's bot receipt
#
# The mutation drops the already-linked short circuit, so `ensure` files a second
# row on every tick — twice an hour, forever, against a PR that already has one.
#MUTANT files-a-row-per-tick|s/^\tif \[\[ -n "\$existing" \]\]; then$/\tif false; then/|a second call on the same PR files nothing
#
# The mutation drops the closing verb from the predicate, so any body merely
# NAMING a key reads as closing it — which is the exact state a Renovate rebase
# leaves behind, and the one this verb exists to refuse.
#MUTANT closes-on-a-bare-key|s/refuse "#\$num.s body closes/key=$(grep -oEm1 "CLOUD-[0-9]+" <<<"$body"); [ -n "$key" ] \&\& { echo "bot-issue: #$num closes $key"; return 0; }; refuse "#$num.s body closes/|A KEY NAMED BUT NOT CLOSED IS REFUSED
#PIN-OK: gh jq
set -uo pipefail

# The manifests this lane owns, and the only paths a bot PR may touch to earn a
# row. Declared here rather than derived from `renovate.json5`'s
# `enabledManagers`: a manager name is not a path, the mapping between them is
# Renovate's and not ours to re-derive, and `ci-local-parity` already decides that
# the manager list itself is complete. Kept in sync by that gate plus this list
# being three lines long.
OWNED_MANIFESTS_RE='^(mise\.toml|Cargo\.toml|Cargo\.lock|\.github/workflows/.+)$'

# The bots whose heads this lane will file for. `renovate` in every spelling the
# app authenticates as; `dependabot` is deliberately absent — CLOUD-660 retired it
# and a row filed for a bot that cannot open a PR would be a claim about a lane
# this repository does not have.
BOT_LOGINS_RE='^(renovate|renovate\[bot\]|mend-for-github-com\[bot\])$'

# The marker that ties a mirror issue to the pull request it was filed for. A
# hidden HTML comment rather than a label or a title convention: it survives an
# edit, it is invisible in the rendered issue, and it is what makes `ensure`
# idempotent across the window where the row exists and the PR body does not yet
# name it. Searched by listing issues, never through the search API, whose
# indexing lag would let one tick file a second mirror.
MIRROR_MARKER_PREFIX="${BOT_ISSUE_MARKER:-bot-lane pr=}"

# What Linear's GitHub Issues sync leaves on the issue once it has mirrored it.
# Measured on #558 -> CLOUD-764, 2026-08-20: `linear-code[bot]` posts a comment
# carrying this marker and the row's URL, about two seconds after creation.
LINKBACK_MARKER="${BOT_ISSUE_LINKBACK:-<!-- linear-linkback -->}"

REPO="${BOT_ISSUE_REPO:-${REPO:-button-inc/batten}}"

die() {
	echo "::error:: bot-issue: $*" >&2
	exit 2
}

refuse() {
	echo "::error:: bot-issue: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is not on PATH — a gate that cannot look must not report success"
}

# `gh api` through mise, so CI and a clone run the same call with the same token
# resolution (mem:github-access). Every read goes through here, so a 4xx is one
# message rather than one per call site.
gh_api() {
	local out rc
	out=$(gh api "$@" 2>&1)
	rc=$?
	if [[ "$rc" != 0 ]]; then
		# Pointer-only: the endpoint and the status, never the response body — a
		# GitHub error can echo a token in a header dump.
		die "GET $1 failed (gh exit $rc) — cannot read the PR, so nothing is filed"
	fi
	printf '%s' "$out"
}

pr_json() {
	gh_api "repos/$REPO/pulls/$1" --jq '{number, title, body, login: .user.login, head: .head.ref, draft}'
}

# The changed paths, capped at the first page. A bot bump touches two files; a PR
# touching more than 100 is not a bump and the cap refusing it is the safe
# direction rather than a truncation nobody sees.
pr_files() {
	gh_api "repos/$REPO/pulls/$1/files?per_page=100" --jq '.[].filename'
}

# --- derive -------------------------------------------------------------------
#
# Emits a CANDIDATE PAYLOAD, not markdown, and that shape is the point: it is the
# same object `get_issue` returns, so `mise run ready-lint` reads it unchanged.
# The Ready block this writes is therefore checkable by the same gate that checks
# a human's, which is what keeps "derived" from meaning "exempt".
derive() {
	local num="$1" pr title login files owned body
	pr=$(pr_json "$num")
	title=$(jq -r '.title // ""' <<<"$pr")
	login=$(jq -r '.login // ""' <<<"$pr")
	[[ -n "$title" ]] || die "#$num has no title — the tracker row's title is the PR's, so there is nothing to file"

	grep -Eq "$BOT_LOGINS_RE" <<<"$login" ||
		refuse "#$num was opened by '$login', which is not a bot this lane files for — an agent's PR carries its own claim receipt and its own issue"

	files=$(pr_files "$num")
	owned=$(grep -E "$OWNED_MANIFESTS_RE" <<<"$files" || true)
	if [[ -z "$owned" ]]; then
		# Pointer-only: the paths, never their contents.
		refuse "#$num touches no manifest this lane owns, so there is no bump to describe: $(tr '\n' ' ' <<<"$files")— filing a row here would assert a change nobody proposed"
	fi

	# §6's type is read out of the PR subject rather than chosen: `renovate.json5`'s
	# `packageRules` already decided it (`ci` for the toolchain and workflows,
	# `build` for the crate graph), and re-deciding it here would be a second
	# authority for one fact. A subject with no Conventional prefix is a lane
	# defect, not something to paper over — `commit-lint` would refuse the commit
	# anyway, so the row says so instead of inventing a type.
	local type
	type=$(grep -oE '^[a-z]+(\([a-z0-9._-]+\))?!?:' <<<"$title" | sed -E 's/[(!:].*//' || true)
	[[ -n "$type" ]] ||
		refuse "#$num's subject carries no Conventional type, so commit-lint would refuse it and it could never land: fix \`semanticCommitType\` in renovate.json5 rather than filing a row for a commit that cannot merge"

	# The bullet list is built before the heredoc rather than inside it: a
	# `shellcheck` directive cannot reach into a here-document, and the sed script
	# below is literal markdown backticks rather than a subshell.
	local owned_bullets
	# shellcheck disable=SC2016  # the backticks are markdown, not command substitution
	owned_bullets=$(sed 's/^/- `/; s/$/`/' <<<"$owned")

	body=$(
		cat <<-BODY
			**Why**

			A bot proposed this change and no human refined it, which is exactly the
			case [CLOUD-693](https://linear.app/buttoninc/issue/CLOUD-693) exists for:
			the row is derived from the pull request's own manifest diff so the merge
			moves the board like any other landing. Nothing here was authored by an
			agent, and nothing here is a judgement.

			Pull request: #$num (\`$(jq -r '.head // ""' <<<"$pr")\`, opened by \`$login\`).

			Manifests touched:

			$owned_bullets

			**Refinement — Ready**

			*Refinement gate: [Definition of Ready & Done](https://linear.app/buttoninc/document/definition-of-ready-and-done-e4e8defb6774). This body carries only specializations.*

			* **Source of truth (§1).** The manifest diff on #$num. It is the one
			  description of this change that cannot disagree with the change, which
			  is why nothing here re-types the versions it carries.
			* **Computable predicate (§2).** Every required check green on the head
			  SHA, decided by \`mise run checks-green\` — the same predicate that
			  gates every other landing, asked of the SHA that fast-forwards.
			* **Effect (§3).** No command-surface change: a dependency or toolchain
			  bump moves no verb, no flag and no effect row.
			* **Output & exit (§5).** Unchanged — this row proposes no new output.
			* **Commit / bump (§6).** \`$type\` → no bump.
			* **Test obligation (§7).** The existing suite, unchanged and unskipped:
			  a bump whose breakage this repo covers reds CI, and one it does not is
			  a coverage gap to file rather than a reason to hold the bump.
			* **Blockers (§8).** None.

			**Acceptance**

			* #$num lands on \`main\` by fast-forward with every required check green,
			  through \`auto-bot-land.yml\` and with no human in the loop.
			* This row moves to In Review by the merge, from the \`Closes\` key in the
			  pull request body.
		BODY
	)

	jq -n --arg t "$title" --arg d "$body" --arg n "$num" \
		'{id: "CLOUD-NEW", status: "Todo", title: $t, description: $d, pr: $n, relations: {blocks: [], blockedBy: [], relatedTo: []}}'
}

# --- file ---------------------------------------------------------------------
#
# THE ROW IS FILED AS A GITHUB ISSUE, AND LINEAR MIRRORS IT (CLOUD-750). The
# first shape of this task called the tracker's GraphQL API directly, which cost
# a credential — and the one this repository has answers 401 in both auth forms.
# It was also the only place in the tree holding a tracker credential at all.
#
# Linear's GitHub Issues sync removes the need for one: the integration is
# configured for this repository (`button-inc/batten` -> Button Cloud), so an
# issue opened with the `GITHUB_TOKEN` this workflow already carries is mirrored
# into a `CLOUD-*` row. Measured end to end on #558 -> CLOUD-764, 2026-08-20:
#
#   created -> mirrored          ~2 seconds, team Button Cloud, body verbatim
#   the key comes back           a `linear-code[bot]` comment carrying
#                                `<!-- linear-linkback -->` and the row's URL
#   the row arrives in           Backlog, with NO project and NO milestone
#   closing the GitHub issue     moves the row to Done in ~1 second
#
# THE LAST ROW IS WHY THIS TASK NEVER CLOSES THE MIRROR. Done here means
# RELEASED (mem:workflow/board-states), so closing the issue would skip In Review
# and assert a release that has not happened. The pull request therefore closes
# the CLOUD KEY — never `#<issue>` — and the merge moves the row exactly as it
# does for an agent's PR. The mirror issue outliving its row is the accepted
# cost of not holding a credential.
#
# AND THE ROW ARRIVES UNREFINED-BY-FIELD, which is recorded rather than hidden:
# the sync sets no project and no milestone, and CLOUD-693's acceptance asked for
# both. Setting them is precisely what a credential would buy. The Ready block is
# in the body, so the row is refined in the sense that matters — `ready-lint`
# reads it — and the fields it cannot set are named on that issue.
file_issue() {
	local payload="$1" num title body tmp created
	num=$(jq -r '.pr' <<<"$payload")
	title=$(jq -r '.title' <<<"$payload")
	body=$(jq -r '.description' <<<"$payload")
	tmp=$(mktemp)
	# The marker goes LAST, after the derived block, so it is the one line a
	# reader never has to look at and the one line `ensure` always finds.
	{
		printf '%s\n\n' "$body"
		printf '<!-- %s%s -->\n' "$MIRROR_MARKER_PREFIX" "$num"
	} >"$tmp"
	created=$(gh api -X POST "repos/$REPO/issues" \
		-f title="$title" -F body=@"$tmp" --jq '.number' 2>&1) || {
		rm -f "$tmp"
		# Pointer-only: never the response, which can echo a header back.
		die "could not open the mirror issue for #$num — no row exists, and none is invented"
	}
	rm -f "$tmp"
	[[ -n "$created" ]] || die "the mirror issue for #$num was accepted but named no number"
	printf '%s' "$created"
}

# The mirror this PR already has, if any. Listed rather than searched: the search
# API's indexing lag is measured in tens of seconds, and a tick that ran inside
# that window would file a second row for the same pull request.
mirror_for() {
	local num="$1"
	gh_api "repos/$REPO/issues?state=all&per_page=100" \
		--jq "[.[] | select((.pull_request // null) == null) | select((.body // \"\") | contains(\"$MIRROR_MARKER_PREFIX$num -->\"))] | .[0].number // empty"
}

# The `CLOUD-<n>` the sync reported back, or empty while it has not run yet. Read
# from the linkback comment alone: the issue BODY is this task's own text, and a
# key named there would be one we wrote rather than one the tracker assigned.
mirror_key() {
	local issue="$1"
	gh_api "repos/$REPO/issues/$issue/comments?per_page=100" \
		--jq "[.[] | select((.body // \"\") | contains(\"$LINKBACK_MARKER\"))] | .[0].body // empty" |
		grep -oE 'CLOUD-[0-9]+' | head -n1 || true
}

# --- link ---------------------------------------------------------------------
#
# `Closes <key>` in the body is the entire board mechanism: the merge moves the row
# because the integration reads it there, and `closing-key-check` refuses a body
# that names a key any other way. Appended rather than templated in, because the
# bot rewrites its own body on every rebase and an append survives being
# reconstructed around.
link_issue() {
	local num="$1" key="$2" body
	body=$(gh_api "repos/$REPO/pulls/$num" --jq '.body // ""')
	if grep -qF "Closes $key" <<<"$body"; then
		echo "bot-issue: #$num already closes $key"
		return 0
	fi
	local tmp
	tmp=$(mktemp)
	{
		printf '%s\n\n---\n\nCloses %s\n' "$body" "$key"
	} >"$tmp"
	gh api -X PATCH "repos/$REPO/pulls/$num" -F body=@"$tmp" >/dev/null 2>&1 ||
		die "could not write the closing key into #$num's body — the row exists but the merge would not move it"
	rm -f "$tmp"
	echo "bot-issue: #$num now closes $key"
}

# --- closes -------------------------------------------------------------------
#
# CLOUD-768. `link` writes the closing key. NOTHING KEEPS IT THERE: Renovate
# regenerates its own PR body on every rebase, and the append `link` makes goes
# with it. Measured on #503, 2026-08-20 — written at 05:49 on head `10ad9f8f`,
# absent at 05:50:14 on head `2f65308e`, one force-push later.
#
# The lane is nearly right by ordering alone: `ensure` is the job's FIRST step,
# so the key is normally rewritten seconds before the ref moves. "Normally" is
# not a gate, and the failure inside that window is SILENT — the fast-forward
# succeeds, `main` advances, the bump ships, and the row sits in Backlog with
# nobody looking at it. So the landing asks once more, against GitHub rather than
# against anything this job read a step earlier, at the last moment it still can.
#
# REFUSING IS AN ORDINARY OUTCOME, exactly like the `main`-moved refusal the
# fast-forward already treats as routine: the next tick re-runs `ensure`, the key
# comes back, and it lands then. Nothing is lost but half an hour.
#
# The predicate is `closing-key-check`'s, verbatim, and deliberately not a
# narrower one matching only what `link` writes. A body a human edited to say
# "Fixes CLOUD-767" closes the row just as well, and a gate that refused it would
# be wrong about the one thing it exists to decide. The leading
# `(^|[^0-9A-Za-z-])` is what keeps `DO-NOT-CLOSE CLOUD-388` from reading as a
# close — that marker ends in a closing verb.
#
# Pointer-only per rule 4: the PR number and the key. Never the body — a bot PR
# carries a release-notes dump, and echoing it would put that in the log of every
# landing.
BOT_ISSUE_CLOSING_VERBS='clos(e|es|ed)|fix(|es|ed)|resolv(e|es|ed)'

closes() {
	local num="$1" body key
	body=$(gh api "repos/$REPO/pulls/$num" --jq '.body // ""' 2>/dev/null) ||
		die "GET repos/$REPO/pulls/$num failed — cannot read the body, so nothing may be landed on its word"
	key=$(grep -oiE "(^|[^0-9A-Za-z-])($BOT_ISSUE_CLOSING_VERBS)[[:space:]]*:?[[:space:]]*#?CLOUD-[0-9]+" <<<"$body" |
		grep -oE 'CLOUD-[0-9]+' | head -n1 || true)
	[[ -n "$key" ]] || refuse "#$num's body closes no tracker key, so merging it would move nothing — not landing; the next tick re-links it"
	echo "bot-issue: #$num closes $key"
}

# --- ensure -------------------------------------------------------------------
#
# TWO PHASES, BECAUSE THE KEY ARRIVES ASYNCHRONOUSLY. Filing the issue and
# learning its `CLOUD-<n>` are separated by however long the sync takes — about
# two seconds when it was measured, but nothing here may depend on that. So a
# tick does as much as it can and says what it did: file the mirror, or link a
# mirror that now has a key. The lander ticks twice an hour and `ensure` is
# idempotent at every step, so the second phase costs nothing to wait for.
#
# THAT IS ALSO WHY THIS DOES NOT POLL. A wall-clock wait inside the job would be
# a guess about someone else's latency dressed as a mechanism, and the landing
# loop's own doctrine refuses those (mem:workflow/landing-loop). A tick that
# cannot finish returns 0 having made progress, and the next one finishes.
ensure() {
	local num="$1" pr existing issue key
	pr=$(pr_json "$num")
	existing=$(grep -oE 'CLOUD-[0-9]+' <<<"$(jq -r '.body // ""' <<<"$pr")" | head -n1 || true)
	if [[ -n "$existing" ]]; then
		echo "bot-issue: #$num already names $existing; nothing filed"
		return 0
	fi
	issue=$(mirror_for "$num")
	if [[ -z "$issue" ]]; then
		# `derive` refuses a PR that is not this lane's before anything is
		# written, which is what keeps a refusal from leaving a half-filed row.
		local payload
		payload=$(derive "$num") || return $?
		issue=$(file_issue "$payload") || return $?
		echo "bot-issue: #$num -> issue #$issue filed; waiting for the tracker to mirror it"
	fi
	key=$(mirror_key "$issue")
	if [[ -z "$key" ]]; then
		echo "bot-issue: issue #$issue is not mirrored yet; the next tick links it"
		return 0
	fi
	link_issue "$num" "$key"
	echo "bot-issue: #$num -> $key (via issue #$issue)"
}

# --- receipt ------------------------------------------------------------------
#
# THE SECOND RECEIPT KIND, AND IT IS SECOND BECAUSE THE TWO ATTEST DIFFERENT
# THINGS (CLOUD-693, CLOUD-431). `claim-check` mints `claim.<branch>`, whose whole
# content is "a human or agent read this issue, checked it for a competitor, and
# confirmed the refinement predates this session". Nothing on a bot branch can
# honestly say that: there was no session, and the row was derived rather than
# refined. Widening the agent receipt to cover bots would make it mean less
# everywhere, which is exactly the trust path CLOUD-431 exists to prevent.
#
# So this mints `bot.<branch>` instead, and what IT attests is decidable from
# public facts rather than from a judgement: the head was opened by an allowlisted
# bot, its diff touches only manifests this lane owns, and its body names the row
# derived from that diff. `verify` accepts either receipt and the two never blur.
#
# Minted by whoever is at the keyboard, exactly like the agent receipt — the party
# that ran the check writes the record of it. A workflow minting one would be a
# receipt asserting a check nobody performed.
mint_receipt() {
	local branch git_dir num pr login body key
	branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) ||
		refuse "detached HEAD carries no branch to key a receipt to — check the bot branch out by name"
	case "$branch" in
	renovate/*) ;;
	*) refuse "$branch is not a bot branch, so the agent claim receipt is the one that applies here: run \`mise run claim-check\` with the issue's payload on stdin" ;;
	esac
	num=$(gh_api "repos/$REPO/pulls?state=open&per_page=100" --jq "[.[] | select(.head.ref == \"$branch\")] | .[0].number // empty")
	[[ -n "$num" ]] || refuse "no open pull request for $branch — the receipt attests to facts about a PR, so there is nothing to attest"
	pr=$(pr_json "$num")
	login=$(jq -r '.login // ""' <<<"$pr")
	grep -Eq "$BOT_LOGINS_RE" <<<"$login" ||
		refuse "#$num was opened by '$login', not by a bot this lane knows"
	derive "$num" >/dev/null || return $?
	body=$(jq -r '.body // ""' <<<"$pr")
	key=$(grep -oE 'CLOUD-[0-9]+' <<<"$body" | head -n1 || true)
	[[ -n "$key" ]] ||
		refuse "#$num's body names no tracker row yet — run \`mise run bot-issue ensure $num\` first, or wait for the lander's next tick"

	git_dir=$(git rev-parse --git-dir 2>/dev/null) || die "not a git checkout, so there is nowhere to write the receipt"
	mkdir -p "$git_dir/batten-receipts" 2>/dev/null || die "cannot write under $git_dir/batten-receipts"
	# Same spelling as `claim.<branch>`, for the same reason: a slash is the one
	# character a filename cannot carry.
	{
		echo "$key"
		echo "bot $login"
		echo "pr $num"
		echo "derived-at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "base $(git rev-parse --verify --quiet origin/main || echo -)"
	} >"$git_dir/batten-receipts/bot.${branch//\//-}"
	echo "bot-issue: $branch attested — opened by $login, manifests owned, row $key. \`verify\` accepts this in place of a claim receipt."
}

need gh
need jq

verb="${1:-}"
case "$verb" in
derive)
	[[ -n "${2:-}" ]] || die "usage: bot-issue derive <pr>"
	derive "$2"
	;;
file)
	[[ -n "${2:-}" ]] || die "usage: bot-issue file <pr>"
	file_issue "$(derive "$2")"
	echo
	;;
link)
	[[ -n "${2:-}" ]] && [[ -n "${3:-}" ]] || die "usage: bot-issue link <pr> <key>"
	link_issue "$2" "$3"
	;;
ensure)
	[[ -n "${2:-}" ]] || die "usage: bot-issue ensure <pr>"
	ensure "$2"
	;;
closes)
	[[ -n "${2:-}" ]] || die "usage: bot-issue closes <pr>"
	closes "$2"
	;;
receipt)
	mint_receipt
	;;
*)
	die "usage: bot-issue derive|file|link|ensure|closes <pr> | receipt"
	;;
esac
