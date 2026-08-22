#!/usr/bin/env bash
#MISE description="Gate: a PR body that names its issue but never in closing form, so the merge will not move the board (reads the body on stdin; pointer-only)"
#
# CLOUD-192. The board's In Review column is written by the tracker's merged-event
# automation, and that automation only fires for a **closing** pull request. A
# PR that merely mentions its issue is a *contributing* PR: it links, it attaches,
# and it moves nothing.
#
# MEASURED, as a controlled pair on one issue — same repository, same branch
# name, same fast-forward landing, same integration settings, one variable:
#
#   #398   body said `Refs: CLOUD-192`     merged 06:27:05   never moved
#   #400   body said `Closes CLOUD-192`    merged 06:59:39   In Review 06:59:41
#
# Two seconds against never. CLOUD-192 was returned to In Progress before the
# second run so the transition was observable rather than a no-op.
#
# WHY THIS NEEDS A GATE RATHER THAN A LINE IN AGENTS.md. `issue-guard` already
# forces a `CLOUD-<n>` onto every PR — in the branch, a commit, or the command —
# so every PR this repo produces names its issue and NONE of them close it. The
# convention was therefore satisfied and the outcome still wrong, which is the
# definition of prose being feedforward only. It is also invisible when broken:
# nothing turns red, the PR merges, and the board is quietly one column behind.
# That is precisely the shape AGENTS.md's rule 2 exists for.
#
# WHERE IT RUNS. `land` pipes the PR body in before readying, beside
# `deferral-check` — same body, fetched once, same lap discipline. Readying is
# the commitment to review, and the board move is what tells everyone review is
# open, so this is the honest moment to insist on it. Not at `gh pr create`: a
# draft body is still being written.
#
# NOT EVERY PR SHOULD CLOSE ITS ISSUE, and pretending otherwise would trade this
# defect for a worse one. Trunk-based work lands several PRs per issue
# (CLOUD-186), and marking each one closing would move the issue to In Review on
# the first landing while the work is half in — CLOUD-468's defect exactly. So a
# PR that deliberately does not complete its issue says so, with the same
# `DO-NOT-CLOSE` marker `mise-tasks/released.sh` already defines for the issue side.
# One token across both, because a second vocabulary for "not finished yet" is a
# second thing to drift; `released` states its meaning and this reuses it.
#
# A BODY NAMING NO KEY AT ALL IS NOT THIS GATE'S BUSINESS. `issue-guard` owns
# that, at `gh pr create`, which is earlier and cheaper. Judging it here too
# would give one rule two authorities.
#
# Pointer-only (non-negotiable 4): the keys and the verdict, never a line of the
# body.
set -euo pipefail

# The opt-out, and the same string `released` matches on the issue side. Stated
# here rather than in each PR's prose, so declining to close is copying a token
# rather than inventing a phrasing this has to recognise.
HOLD_MARKER='DO-NOT-CLOSE'

# GitHub's closing keywords, which the tracker's integration honours. All three
# verbs in all three inflections; `-i` makes the case-insensitivity explicit
# rather than doubling the alternation.
CLOSING_VERBS='clos(e|es|ed)|fix(|es|ed)|resolv(e|es|ed)'

LIST_ONLY=
case "${1:-}" in
--list) LIST_ONLY=1 ;;
"") ;;
*)
	echo "usage: closing-key-check [--list]  (PR body on stdin)" >&2
	exit 2
	;;
esac

# Exit 2 is "I could not read the input", distinct from exit 1 "this PR will not
# move the board" — a caller piping nothing must not look like a passing body.
if ! body=$(cat) || [[ -z "${body//[[:space:]]/}" ]]; then
	echo "::error:: stdin is empty; expected a PR body" >&2
	exit 2
fi

# Bounded on both sides so CLOUD-17 is not satisfied by a mention of CLOUD-179 —
# the same match `landed-check` and `done-check` use.
named=$(grep -oiE '(^|[^0-9A-Za-z-])CLOUD-[0-9]+([^0-9]|$)' <<<"$body" |
	grep -oiE 'CLOUD-[0-9]+' | tr '[:lower:]' '[:upper:]' | sort -u | sort -t- -k2,2n || true)

if [[ -z "$named" ]]; then
	# Not this gate's question, and it is answered earlier and elsewhere: the
	# engine's `pr-names-an-issue` row refuses `gh pr create` on work naming no
	# key at all (CLOUD-446). Named as the rule rather than as `issue-guard`,
	# which that change retired — a pointer at a deleted program is a second
	# authority that no longer exists.
	echo "closing-key-check: the body names no CLOUD key — the pr-names-an-issue rule owns that case"
	exit 0
fi

# The keyword and the key must be adjacent, which is what the integration
# actually parses: `Closes CLOUD-192`, optionally through a `:` or `#`. A body
# with the word "fixes" in one paragraph and a key in another does not close
# anything, and must not read as though it does.
# LEFT-BOUNDED, and the boundary excludes `-` for one specific reason: the hold
# marker this file defines ENDS IN THE CLOSING VERB. `DO-NOT-CLOSE CLOUD-388` —
# the marker used in its most natural form, naming the issue it declines to
# close — matched `clos(e)` followed by the key and was reported as CLOSING that
# issue. The opt-out was unusable exactly when it was written correctly, and it
# failed as the inverse of the author's intent rather than as a refusal, which
# is the silent direction.
#
# `[^0-9A-Za-z-]` is the same bounded-match idiom the `named` scan above already
# uses, so this is that file convention applied rather than a new one. It keeps
# the #404 case intact: `Closes CLOUD-192` after a line start or a space still
# matches, and a body that merely DISCUSSES the marker still cannot excuse a
# real close.
closing=$(grep -oiE "(^|[^0-9A-Za-z-])($CLOSING_VERBS)[[:space:]]*:?[[:space:]]*#?CLOUD-[0-9]+" <<<"$body" |
	grep -oiE 'CLOUD-[0-9]+' | tr '[:lower:]' '[:upper:]' | sort -u | sort -t- -k2,2n || true)

# CLOSING IS TESTED FIRST, and the order is a fix rather than a preference. An
# explicit `Closes <key>` is the strongest statement a body can make about the
# board, so nothing else in it should be able to override that — and with the
# opt-out tested first, a body that merely DISCUSSED the marker was excused from
# a check it passed on the merits.
# `--list` PRINTS THE KEYS AND DECIDES NOTHING (CLOUD-774), so a sibling gate can
# ask "does this body close CLOUD-N?" without owning a second copy of
# `$CLOSING_VERBS`. `filed-here-check` needs exactly that to exempt a row the PR
# closes, and a duplicated regex would be one value in two files with no gate
# holding them equal — the defect CLOUD-769 and CLOUD-770 are about, which makes
# copying it here self-refuting rather than merely untidy.
#
# It sits AFTER the extraction and BEFORE every verdict branch: the flag changes
# what is emitted, never what is matched, so the two callers can never disagree
# about what a closing key is. Empty output with exit 0 means "this body closes
# nothing", which is a usable answer and not a refusal.
if [[ -n "${LIST_ONLY:-}" ]]; then
	[[ -n "$closing" ]] && printf '%s\n' "$closing"
	exit 0
fi

if [[ -n "$closing" ]]; then
	echo "closing-key-check: closes $(tr '\n' ' ' <<<"$closing" | sed 's/ $//') — the merge will move the board"
	exit 0
fi

# ANCHORED TO THE START OF A LINE, because a body that TALKS ABOUT the marker is
# not using it — the same distinction the adjacency rule above draws for the
# closing verb, and the same substring hazard the `forbid` rows in `batten.toml`
# document (a rule over a directory that would otherwise fire on its own
# explanation).
#
# Found by this gate's own first live outing: PR #404 carries `Closes CLOUD-192`
# AND documents `DO-NOT-CLOSE` in its prose, and the unanchored form excused it
# as an opt-out. Both halves of that are now fixed — the close is read first, and
# a mention no longer counts as a use.
if grep -qE "^[[:space:]]*$HOLD_MARKER" <<<"$body"; then
	echo "closing-key-check: $HOLD_MARKER — this PR declines to complete its issue, so the board is not expected to move"
	exit 0
fi

{
	echo "::error:: this PR names its issue but never in closing form, so merging it will move nothing:"
	while IFS= read -r id; do
		[[ -n "$id" ]] || continue
		echo "  $id  named, not closed"
	done <<<"$named"
	echo "Write \"Closes <key>\" in the PR body (fixes/resolves also work), or add $HOLD_MARKER if this PR is not meant to complete it."
} >&2
exit 1
