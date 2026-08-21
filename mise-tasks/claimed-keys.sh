#!/usr/bin/env bash
#MISE description="The issue keys a branch CLAIMS, as distinct from the ones it merely mentions (extra evidence on stdin; prints one key per line)"
#
# CLOUD-338. Two guards need this answer and had one copy of it. `issue-guard`
# derived the claimed set inline to refuse a duplicate claim; `deferral-check`
# then needed the same set, to stop a deferral being exempted by the very key
# `issue-guard` forces onto every PR. A second copy is a second authority, and
# two guards that disagree about which issue a PR claims is a worse defect than
# either gate misfiring — so the derivation moved here and both read it.
#
# WHICH issue a branch claims is a NARROWER question than which it mentions,
# and conflating them is a false positive `issue-guard` produced against its own
# PR twice. A body cites related issues, prior measurements and superseded work
# as evidence; a branch may carry a bundle name naming two issues that landed
# hours ago. Neither is a claim. Only these are, most explicit first:
#
#   1. a closing keyword — `Closes`/`Fixes`/`Resolves CLOUD-<n>` — in the extra
#      evidence on stdin (the command being run, or the PR's own body) or in a
#      commit on the branch. It OVERRIDES the branch, which is the escape hatch
#      for a branch whose name no longer reflects the work.
#   2. failing that, the branch name — the tracker's own `gitBranchName` shape
#      names the issue being worked, so a branch is a claim — together with the
#      PR TITLE where a caller supplies one (see the explicit sources below).
#   3. failing that, a `Refs:` trailer on a commit.
#
# When none resolves, the answer is EMPTY and that is not an error: every caller
# treats "no claim" as "do not judge", because a guard that guesses is one that
# blocks correct work. Outside a git repo the same applies — exit 0, print
# nothing, and let the caller behave exactly as it did before it asked.
#
# EXPLICIT SOURCES, for a PR this checkout did not author (CLOUD-378).
# `issue-guard` asks the same question about a COMPETING PR — which issue does
# *it* claim — and had no way to ask it here, because the three sources above are
# all read from the local repository. So it re-derived the answer inline with a
# bare mention of the key in the other PR's title or body, which is the
# conflation this whole file exists to refuse, applied to the other side of the
# comparison. Measured: PR #306 (`docs(agents): … (CLOUD-268)`) cites CLOUD-133
# in one row of an evidence table and was reported as claiming it.
#
#   --closing-only    answer from source 1 ALONE — a closing keyword — and never
#                     fall through to the branch name or a `Refs:` trailer.
#                     For a caller asking about a LOG rather than a branch
#                     (CLOUD-804): over `main`'s history the fallbacks answer a
#                     different question, and source 3 in particular is the exact
#                     citation signal CLOUD-480 was swept wrong on. Opt-in, so
#                     every existing caller keeps the full chain.
#   --branch <name>   the head branch, standing in for source 2
#   --title <text>    the PR title, ALSO source 2 — for a PR you did not author
#                     the title is the other self-declaration of what the work
#                     is, and this repo's own convention ends every title with
#                     `(CLOUD-<n>)`. A body is not: a body cites evidence.
#   --log <text>      commit messages, standing in for sources 1 and 3
#
# Passing ANY of them switches to explicit mode: git is not consulted at all and
# an unsupplied source is empty. All-or-nothing rather than per-source fallback,
# because a remote PR silently answered from the local branch would be the
# worst kind of wrong — a confident verdict about the wrong repository state.
# Source 2 is the UNION of branch and title, not a precedence between them: they
# are two spellings of one self-declaration, and picking one would make the
# answer depend on which the author happened to fill in.
#
# Output is the keys alone, uppercased and sorted, one per line — a pointer set,
# never the prose they were extracted from (rule 4).
# The mutation drops the speculation boundary, so a key carried only by an adopted
# commit is claimed again and the waiter races the PR it is waiting on.
# The mutation makes --closing-only fall through anyway, so a `Refs:` citation is
# read as a claim — CLOUD-480's shape, which is the whole reason the flag exists.
#MUTANT claimed-keys-closing-only-falls-through|s/^if \[ "\$closing_only" -eq 0 \]; then$/if true; then/|--closing-only does not fall through to a Refs: trailer
#MUTANT claimed-keys-adopts-speculated|s/^\tif since=\$(spec_base_range); then$/\tif false; then/|a key carried only by a speculated commit is not claimed
set -euo pipefail

ISSUE_RE='CLOUD-[0-9]+'
CLAIM_RE='(Closes|Fixes|Resolves)[[:space:]]+CLOUD-[0-9]+'

# `grep -o` consumes its whole input rather than exiting on the first hit, so
# piping it is safe under pipefail — the SIGPIPE trap that bit `issue-guard`
# applies to `-q`/`-m`/`-l` only.
extract() { grep -oiE "$ISSUE_RE" <<<"$1" | tr '[:lower:]' '[:upper:]' | sort -u || true; }

# Extra evidence the caller has and this script cannot read for itself: the
# command being guarded, or the PR body being judged. Optional — a caller with
# nothing to add closes stdin and the branch/commit sources still answer.
extra=""
[ -t 0 ] || extra=$(cat || true)

explicit=0
closing_only=0
branch=""
title=""
log=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--branch | --title | --log)
		# A flag with no value is a caller bug, not an empty source: silently
		# reading the next flag as the value would answer about the wrong text.
		[ "$#" -ge 2 ] || {
			echo "::error:: claimed-keys: $1 needs a value" >&2
			exit 2
		}
		case "$1" in
		--branch) branch="$2" ;;
		--title) title="$2" ;;
		--log) log="$2" ;;
		esac
		explicit=1
		shift 2
		;;
	--closing-only)
		closing_only=1
		shift
		;;
	*)
		echo "::error:: claimed-keys: unknown argument" >&2
		exit 2
		;;
	esac
done

# THE COMMITS THIS BRANCH AUTHORED, WHICH IS NARROWER THAN THE ONES IT CARRIES
# (CLOUD-748). `land`'s speculative linearization (CLOUD-369) rebases a waiting
# branch onto the lease holder's published head, and says so plainly: it "puts
# ANOTHER BRANCH'S unlanded commits into this branch's history". Those commits
# carry the holder's `CLOUD-*` keys, and the holder has an open PR by
# construction — so `claim-race-check`, reading this file, reported the waiter as
# racing the very PR the speculation bet on. Measured twice in one session, on
# CLOUD-718 and then CLOUD-719, each costing a full `verify`.
#
# It is not a race and it is not intermittent: the two gates were individually
# correct and jointly unsatisfiable. `land` would have unwound the bet at the top
# of the next lap, but a refused gate ends the lap, so the settle never ran.
#
# `BATTEN_SPEC_BASE` is the boundary, exported by `land` when it speculates and
# cleared when it settles. It is the commit the branch was replayed ONTO, so
# everything after it on HEAD is this branch's own work — not `spec_undo`, which
# is HEAD *before* the rebase and is left off the branch entirely.
#
# HONOURED ONLY WHEN IT IS AN ANCESTOR OF HEAD, which is what makes a stale
# export harmless: an unwound bet, a `land` that died, or an inherited variable
# from an unrelated run all fail that test and the range falls back to
# `origin/main`. The failure direction is the wider set, which is the one that
# refuses — never the narrower one, which would silently stop catching races.
spec_base_range() {
	local base="${BATTEN_SPEC_BASE:-}"
	[ -n "$base" ] || return 1
	git merge-base --is-ancestor "$base" HEAD 2>/dev/null || return 1
	printf '%s\n' "$base"
}

if [ "$explicit" -eq 0 ]; then
	branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || exit 0
	if since=$(spec_base_range); then
		log=$(git log --format='%B' "$since"..HEAD 2>/dev/null || true)
	elif git rev-parse --verify -q origin/main >/dev/null 2>&1; then
		log=$(git log --format='%B' origin/main..HEAD 2>/dev/null || true)
	fi
fi

claimed=$(extract "$(grep -oiE "$CLAIM_RE" <<<"$extra $log" || true)")
if [ "$closing_only" -eq 0 ]; then
	[ -n "$claimed" ] || claimed=$(extract "$branch $title")
	[ -n "$claimed" ] || claimed=$(extract "$(grep -oiE "Refs:[[:space:]]*CLOUD-[0-9]+" <<<"$log" || true)")
fi

[ -n "$claimed" ] && printf '%s\n' "$claimed"
exit 0
