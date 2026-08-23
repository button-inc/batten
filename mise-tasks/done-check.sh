#!/usr/bin/env bash
#MISE description="Gate: no issue sits Done while no release tag contains its commits (reads get_issue payloads on stdin)"
#
# CLOUD-192. `Done` on this board means **released** ([dor-dod]), and the
# tracker's GitHub integration keys it on the MERGE. Those are different events
# with a release cycle between them, so every issue reads Done from the moment it
# lands — while shipped in nothing.
#
# Measured 2026-08-13. CLOUD-499's state history is `Todo -> In Progress -> Done`
# with Done set at 05:13:12, merge time. The last tag was v0.0.62, cut the
# previous day, and `main` stood 50 commits past it. So ~1.5 days of landed work
# read as released, and `In Review` — the post-merge, pre-release column the
# trunk-based model depends on — was entered only when a human put an issue
# there by hand.
#
# The merge-side half is a tracker setting (map "pull request merged" to In
# Review), not something any code here can hold. What code CAN hold is the
# consequence: a Done that no tag contains is a board that is lying, and that is
# computable from git with no tracker credential.
#
# THE TERMINAL TWIN OF `landed-check`, and built to its shape deliberately:
#
#   landed-check   In Progress, but its ref is on main   ->  In Progress -> In Review
#   done-check     Done, but no tag contains its ref     ->  Done -> In Review
#
# Both report the same target column from opposite sides, which is the point: In
# Review is the truthful column for landed-and-unreleased work, and the two ways
# to be wrong about it are being behind git and being ahead of the release.
#
# `released` is the third member and runs the other direction — given a tag, which
# In Review issues did it ship. That one promotes; this one demotes. Neither
# performs the move: agents fetch, gates decide, and the caller pipes the board in
# because no tracker credential exists.
#
# SHIPPING A REF IS NECESSARY FOR Done, NOT SUFFICIENT — the same caveat
# `released`'s header carries, and for the same reason: refs are resolved from
# commit MESSAGES, so a commit can name an issue to continue it, document it,
# cite it or defer it. That asymmetry decides the direction this gate is safe in.
# A ref inside a tag is weak evidence of Done, so this never CONFIRMS a Done. A
# ref nowhere near a tag is conclusive evidence of not-released, so this only ever
# refutes one. Everything it reports is a Done that cannot be true; a Done it
# stays silent about is merely one it cannot refute.
#
# WHICH ALSO BOUNDS IT, and the bound belongs here rather than in a reader's
# surprise: an issue carrying several PRs is judged by its most-released ref, so
# a Done whose work half-landed and half-shipped passes. That is CLOUD-468's
# question, not this one.
#
# Pointer-only (non-negotiable 4): issue id and target state, never a body.
# Sorted numerically, so re-running is byte-stable and diffable.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT unreleased-done-passes|s/^exit "\$fail"$/exit 0/|landed past the last tag is reported

set -euo pipefail

# Exit 2 is "I could not read the input", distinct from exit 1 "the board is
# ahead of the release" — a caller piping the wrong thing must not look like a
# clean board.
if ! payload=$(cat) || [[ -z "${payload//[[:space:]]/}" ]]; then
	echo "::error:: stdin is empty; expected get_issue payloads" >&2
	exit 2
fi
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$payload" 2>/dev/null) ||
	! jq -e 'all(.[]; has("id") and has("status"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: stdin is not a set of get_issue payloads (need id and status per issue)" >&2
	exit 2
fi

# TWO preconditions, and both are exit 2 rather than a verdict, because each has
# a failure mode that looks like an answer:
#
#   no origin/main  -> nothing is landed, so every Done looks unlanded and this
#                      reports a clean board it never checked (landed-check's
#                      guard, same reason).
#   no tags         -> nothing is released, so every Done looks UNRELEASED and
#                      this fails the entire board. A default CI checkout fetches
#                      no tags, which is the shallow-clone shape `released`'s
#                      header warns about; a run that finds none has not
#                      discovered a catastrophe, it has failed to look.
#
# They fail in opposite directions — false green and false red — which is exactly
# why neither may be inferred from an empty result.
if ! git rev-parse --verify -q origin/main >/dev/null 2>&1; then
	echo "::error:: origin/main does not resolve, so landedness cannot be judged. That is a checkout problem, not a clean board." >&2
	exit 2
fi
if [[ -z "$(git tag -l 'v[0-9]*')" ]]; then
	echo "::error:: no v* tags in this clone, so releasedness cannot be judged. Fetch tags (a default CI checkout has none) — an unreleased-looking board here is a fetch problem, not a finding." >&2
	exit 2
fi

# Read each log ONCE, into a variable. Not an optimisation — `git log … | grep -q`
# under `set -o pipefail` reports failure even when the grep matches: grep exits
# on the first hit, git log takes SIGPIPE, and the pipeline's status becomes that
# signal. The gate then found nothing and reported a clean board, which is the
# silent false green this repo keeps meeting in new disguises.
#
# The two sets are a partition of what matters, expressed in git's own reachability
# rather than by comparing dates or parsing tag names:
#
#   released    every commit reachable from any v* tag — in a published release
#   unreleased  commits on main that no such tag reaches — landed, not shipped
#
# Reachability, not the tag RANGE `released` uses, because the question differs:
# `released` asks "which issues did THIS tag ship" and needs the range; this asks
# "did ANY release ship it" and needs the union.
released=$(git log --format='%B' --tags='v[0-9]*' 2>/dev/null || true)
unreleased=$(git log --format='%B' origin/main --not --tags='v[0-9]*' 2>/dev/null || true)

# Bounded on both sides so CLOUD-17 is not satisfied by a commit naming CLOUD-179.
names() { grep -qE "(^|[^0-9A-Za-z-])$2([^0-9]|$)" <<<"$1"; }

fail=0
unlanded=0
# Byte-stable ordering: numeric by issue number, the `by_num` idiom graph-check uses.
while IFS= read -r id; do
	[[ -n "$id" ]] || continue
	if names "$released" "$id"; then
		continue # a release shipped a commit naming it — this gate cannot refute Done
	fi
	if names "$unreleased" "$id"; then
		[[ "$fail" = 0 ]] && echo "::error:: issues are Done while no release tag contains their commits — landed-but-unreleased is In Review (AGENTS.md, [dor-dod]):" >&2
		echo "  $id  Done -> In Review" >&2
		fail=1
	else
		# A third channel, not a violation — graph-check's `note()` precedent.
		# A Done issue no commit names at all is invisible to git, and git is the
		# only witness this gate has. Board-only work, an issue closed as a
		# duplicate, and everything predating the ref convention all land here.
		# Reporting it would make the gate fail on history it cannot judge; hiding
		# it would make that silence indistinguishable from a pass.
		echo "  $id  unlanded (no commit on main names it — not judged)" >&2
		unlanded=$((unlanded + 1))
	fi
done < <(jq -r '.[] | select(.status == "Done") | .id' <<<"$issues" | sort -u | sort -t- -k2,2n)

if [[ "$fail" = 0 ]]; then
	echo "done-check: every Done issue is in a release ($unlanded not judged)"
fi
exit "$fail"
