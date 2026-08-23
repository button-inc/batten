#!/usr/bin/env bash
#MISE description="Gate: no issue sits In Progress while its commits are already on main (reads get_issue payloads on stdin)"
#
# CLOUD-186. The tracker's open-side automation moves an issue to In Progress
# when a commit mentions it. That is not the same predicate as "work on this
# issue began", and the difference is observable three ways in one session:
#
#   CLOUD-179  sat correctly in In Review; a later commit carrying its ref moved
#              it BACK to In Progress. The work was continuing, not restarting.
#   CLOUD-174  was moved to In Progress and left there after its work landed.
#   CLOUD-191  was started by a commit that only DOCUMENTED the problem, so the
#              board claimed someone was working it when nobody was.
#
# A commit can mention an issue to continue it, to document it, to cite it as
# prior art, or to record a deferral. The automation cannot tell those apart, and
# it only ever moves forward into In Progress — never out. So the column silently
# understates every multi-PR issue, which under trunk-based development is most
# of them.
#
# The predicate that IS computable, from git alone and with no tracker
# credential: an issue in In Progress whose work is on `main` has landed, and
# AGENTS.md defines landed-on-main as In Review.
#
# WHAT COUNTS AS "ON MAIN", AND WHY A MENTION DOES NOT (CLOUD-804). This gate
# spent its whole life deciding that with one bounded grep for the id over
# `main`'s messages — and the paragraph above says in its own words why that is
# the wrong reading: a commit can mention an issue to CONTINUE it, to DOCUMENT
# it, to cite it as PRIOR ART, or to record a DEFERRAL. It refused the tracker's
# automation for conflating those, and then decided `landed` on the same signal.
# `board-move-guard` names the cost: CLOUD-480 was swept to In Review on a
# `Refs:` trailer that named it as the still-open gap, and sat wrong for 4.5h.
#
# Measured 2026-08-20, the first run this predicate ever had over the whole
# column: 19 rows named, of which 2 were closed by a merged PR and 2 were live
# work in an OPEN pull request. It went unnoticed for so long because until
# CLOUD-469 gave this gate a caller it was invoked one issue at a time, where a
# reader could eyeball the verdict. A column sweep cannot.
#
# SO LANDEDNESS IS A DISJUNCTION, and each half exists because the other one
# alone is wrong in a measurable direction:
#
#   1. a commit reachable from `origin/main` CLAIMS the id — a closing keyword,
#      decided by `claimed-keys --closing-only`, which is this repo's one
#      authority on claim-versus-mention (`.claude/rules/toolchain.md`). Never a
#      second copy of its CLAIM_RE; CLOUD-378 was filed for applying it to one
#      side of a comparison and not the other.
#   2. the caller's evidence names a MERGED pull request closing the id.
#
# WHY 1 IS NOT ENOUGH, measured on this repository and not reasoned about: of
# 966 commits on `main`, **31 carry a closing keyword — 3%**. This repo lands by
# fast-forward, so the keyword lives in the PR BODY and never reaches a commit.
# CLOUD-201's commits `f5b9993` and `2bc1ede` are ancestors of `main` with no
# closing key anywhere in the log. A claim-only reading would therefore trade
# over-reporting for a SILENT UNDER-REPORT, which is strictly worse for a drain:
# it stops naming rows that really are behind git, and nothing says so.
#
# WHY 2 IS NOT ENOUGH: a PR must be MERGED. CLOUD-271 and CLOUD-401 were both
# named by citation while their real work sat in open PR #579. An open PR is
# live work, and reporting it landed is the CLOUD-480 error pointed forwards.
#
# THE EVIDENCE COMES FROM THE CALLER, NOT FROM `gh`. The six board-payload gates
# — this one, `graph-check`, `done-check`, `released`, `done-pr-check` and
# `board-move-guard` — are uniformly gh-free, which is the agents-fetch-gates-
# decide split rather than an accident. `claimed-keys` grew `--branch`/`--title`
# for exactly this reason when CLOUD-378 needed it to judge a PR this checkout
# did not author, and `branch-age-check` injects `BRANCH_AGE_PRS` the same way.
# This is a third instance of a settled pattern, not a new one.
#
# This does not claim the work is COMPLETE — that is the release question
# (`released`, CLOUD-174) and a judgement this must not make. It claims only that
# the column is behind the git history, which is a fact.
#
# Agents fetch, gates decide: the caller pipes `get_issue` payloads, same as
# `graph-check` and `ready-lint`. Pointer-only output; byte-stable ordering.
#
#   --merged-prs <file>   `<CLOUD-id><TAB><pr-number>` lines, one per closing key
#                         found in a MERGED pull request's body.
#   --landed-by <file>    `<CLOUD-id><TAB><ref>` lines the caller ASSERTS carry
#                         the work, for rows both halves above are structurally
#                         unable to reach. See "THE THIRD ARM" below.
#
# THE THIRD ARM, AND WHY IT HAD TO EXIST (CLOUD-903). Both halves above turn on a
# CLAIM, which is right. The consequence nobody priced: a key whose work landed
# through a `Refs:`-only pull request satisfies NEITHER, and never will. No later
# event can put a closing key on an already-merged PR, and no later commit will
# claim an id whose work is already on `main`. The row is undrainable by gate,
# permanently, and the gate reports it as not landed — true of the evidence and
# false of the tree.
#
# MEASURED 2026-08-23, over the whole board rather than reasoned about. Against
# `main` at 1180 commits and every merged pull request:
#
#   In Progress            37 rows, ALL 37 undrainable by the two arms above
#     ...mentioned on main   5   (work plausibly landed, no claim anywhere)
#     ...never mentioned    32   (genuinely live work — correctly In Progress)
#   In Review              51 rows, 7 undrainable and mentioned
#
# So the population is SMALL — 5, not 30 — which is what makes a per-row asserted
# arm defensible where a derived one would not be. CLOUD-270 reproduces the row's
# own instance exactly: still undrainable, still mentioned on `main`, its work on
# `main` since 2026-08-09 through PRs #198 and #201, neither of which closes it.
#
# ITS COLUMN HAS NOW BEEN WRONG IN THREE DIRECTIONS, which is the argument for a
# recorded route rather than a hand-move: Done (2026-08-11, by hand) -> In
# Progress (2026-08-21, three seconds after PR #639 merely CITED it) -> Backlog
# (2026-08-22). Landed work now sits in "not yet Ready".
#
# THIS ARM IS AN ASSERTION, NOT A DERIVATION, and the difference is the whole
# reason it is a separate flag. The caller assembles the file, so a wrong line
# lands a row that never landed — the forgery risk is real and is the price of
# reaching rows no derivation can. Three properties keep it honest:
#
#   * It is PER-ID and EXPLICIT. A mention still never counts, anywhere, which is
#     CLOUD-804's distinction surviving intact. Nothing here reads `main`'s log
#     for a bare key; the caller must name the row and the evidence.
#   * It is REPORTED SEPARATELY. A row drained by this arm prints `asserted` and
#     names the ref, so a reader can tell an asserted landing from a derived one
#     rather than having to trust the union.
#   * It is OPTIONAL and absent-is-empty, unlike `--merged-prs`. Absent evidence
#     there is exit 2 because it would silently halve a disjunction that is
#     almost always answered by it; absent here is simply "no assertions", which
#     is the ordinary case and cannot manufacture a false green.
#
# ABSENT EVIDENCE IS EXIT 2, NEVER A SHORT SWEEP. Without the file, half the
# disjunction cannot be evaluated and this would report a near-clean column it
# never checked — at 3% commit-keyword coverage, "clean" would be the answer
# almost always. That is the silent false green this file has met twice already
# (the SIGPIPE read below, and the unresolvable origin/main above), arriving a
# third time in a new disguise. `released` learned the same lesson in CLOUD-783:
# a payload that cannot answer is refused by name, not swept.
#
# The mutations target each half of the disjunction. The first makes a bare
# mention count again; the second drops the merged-PR half, which is the
# under-report the 3% measurement predicts.
#MUTANT landed-check-mention-is-a-landing|s@^if ! claimed_ids=.*@claimed_ids=$(jq -r '.[].id' <<<"$issues"); if false; then@|CLOUD-804: a commit citing an id as PRIOR ART does not land it
#MUTANT landed-check-ignores-merged-prs|s@^if ! merged_ids=.*@merged_ids=""; if false; then@|CLOUD-804: commits on main with the key only in a MERGED PR body still land it
# The third arm's two properties, each of which alone would make it dishonest.
# The first drops the arm entirely, which puts CLOUD-903's population back to
# permanently undrainable. The second collapses its report into the derived
# halves, so a reader can no longer tell the caller's word from evidence.
#MUTANT landed-check-ignores-asserted|s@^landed=\$(printf@asserted_ids=""; landed=$(printf@|an asserted landing drains a row no derived half can reach
#MUTANT landed-check-hides-assertion|s@(asserted by --landed-by: [$][{]ref:-no ref given[}])@@|an asserted landing is REPORTED as asserted, never as derived
set -euo pipefail

merged_prs=""
landed_by=""
have_evidence=0
while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--merged-prs)
		[[ "$#" -ge 2 ]] || {
			echo "::error:: landed-check: --merged-prs needs a value" >&2
			exit 2
		}
		merged_prs="$2"
		have_evidence=1
		shift 2
		;;
	--landed-by)
		[[ "$#" -ge 2 ]] || {
			echo "::error:: landed-check: --landed-by needs a value" >&2
			exit 2
		}
		landed_by="$2"
		shift 2
		;;
	*)
		echo "::error:: landed-check: unknown argument" >&2
		exit 2
		;;
	esac
done

# Exit 2 is "I could not read the input", distinct from exit 1 "the board is
# behind" — a caller piping the wrong thing must not look like a stale board.
if ! payload=$(cat) || [[ -z "${payload//[[:space:]]/}" ]]; then
	echo "::error:: stdin is empty; expected get_issue payloads" >&2
	exit 2
fi
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$payload" 2>/dev/null) ||
	! jq -e 'all(.[]; has("id") and has("status"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: stdin is not a set of get_issue payloads (need id and status per issue)" >&2
	exit 2
fi

# `main` must resolve, or every issue would look unlanded and the gate would
# report a clean board it never checked — the silent false green this repo has
# hit twice before.
if ! git rev-parse --verify -q origin/main >/dev/null 2>&1; then
	echo "::error:: origin/main does not resolve, so landedness cannot be judged. That is a checkout problem, not a clean board." >&2
	exit 2
fi

# Read the log ONCE, into a variable. Not an optimisation — `git log … | grep -q`
# under `set -o pipefail` reports failure even when the grep matches: grep exits
# on the first hit, git log takes SIGPIPE, and the pipeline's status becomes that
# signal. The gate then found nothing and reported a clean board, which is the
# silent false green this repo keeps meeting in new disguises.
log=$(git log --format='%B' origin/main 2>/dev/null || true)

# HALF ONE. `claimed-keys` is the authority, consulted rather than copied. It is
# handed the log explicitly with empty branch/title so nothing about THIS
# checkout leaks into a question about `main`'s history, and `--closing-only`
# because its branch-name and `Refs:` fallbacks answer "what does this branch
# claim", which is a different question and would readmit the citation.
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# THE LOG GOES ON STDIN, NOT IN ARGV. `main`'s history is 1.27 MB here and an
# argv that size is `Argument list too long` — exit 126, which the disjunction
# below would have read as "nothing claimed" and reported as a clean column.
# Measured at construction, and caught only because the failure path refuses:
# the same call with the log in `--log` returned 126 and zero keys. stdin is
# `claimed-keys`' own documented channel for evidence the caller holds, so this
# is the interface it already offers rather than a workaround. The three empty
# explicit sources are what stop it reading THIS checkout's HEAD instead.
if ! claimed_ids=$(printf '%s' "$log" | "$here/claimed-keys.sh" --closing-only --branch "" --title "" --log "" 2>/dev/null); then
	echo "::error:: claimed-keys could not read main's log, so a claim cannot be told from a mention. That is not a clean board." >&2
	exit 2
fi

# HALF TWO. The caller's merged-PR evidence. Unreadable is exit 2 for the same
# reason absent is: a gate that cannot look never reports a clean column.
if [[ "$have_evidence" -eq 0 ]]; then
	echo "::error:: no --merged-prs evidence, so landedness cannot be decided. Only 3% of this repo's commits carry a closing keyword — fast-forward landing puts it in the PR body — so deciding on commits alone would report a clean column it never checked. Supply \`<CLOUD-id><TAB><pr-number>\` lines for merged PRs." >&2
	exit 2
fi
if [[ ! -r "$merged_prs" ]]; then
	echo "::error:: --merged-prs names a file that cannot be read: ${merged_prs}. That is a caller problem, not a clean board." >&2
	exit 2
fi
if ! merged_ids=$(awk -F'\t' 'NF >= 1 && $1 ~ /^CLOUD-[0-9]+$/ { print $1 }' "$merged_prs" | sort -u); then
	echo "::error:: --merged-prs could not be parsed: ${merged_prs}." >&2
	exit 2
fi

# HALF THREE, the asserted arm. Unreadable is exit 2 for the same reason the
# others are — a caller who named a file this cannot open has not supplied an
# empty assertion set, they have supplied one nobody read. Absent is empty, which
# is the ordinary case.
asserted_ids=""
if [[ -n "$landed_by" ]]; then
	if [[ ! -r "$landed_by" ]]; then
		echo "::error:: --landed-by names a file that cannot be read: ${landed_by}. That is a caller problem, not a clean board." >&2
		exit 2
	fi
	if ! asserted_ids=$(awk -F'\t' 'NF >= 1 && $1 ~ /^CLOUD-[0-9]+$/ { print $1 }' "$landed_by" | sort -u); then
		echo "::error:: --landed-by could not be parsed: ${landed_by}." >&2
		exit 2
	fi
fi

# The union is the landed set. All three halves are key sets, so membership is a
# fixed-string whole-line match — never a substring, which is how CLOUD-17 would
# match CLOUD-179.
landed=$(printf '%s\n%s\n%s\n' "$claimed_ids" "$merged_ids" "$asserted_ids" | grep -vE '^[[:space:]]*$' | sort -u || true)

fail=0
while IFS= read -r id; do
	[[ -n "$id" ]] || continue
	if grep -qxF "$id" <<<"$landed"; then
		[[ "$fail" = 0 ]] && echo "::error:: issues are In Progress while their commits are on main — landed is In Review (AGENTS.md):" >&2
		# WHICH ARM DRAINED IT IS PART OF THE FINDING. A derived landing is
		# evidence; an asserted one is the caller's word, and a reader who cannot
		# tell them apart has to trust the union. The ref travels with it so the
		# assertion can be checked rather than taken.
		if [[ -n "$asserted_ids" ]] && grep -qxF "$id" <<<"$asserted_ids" &&
			! grep -qxF "$id" <<<"$claimed_ids" && ! grep -qxF "$id" <<<"$merged_ids"; then
			ref=$(awk -F'\t' -v want="$id" 'NF >= 2 && $1 == want { print $2; exit }' "$landed_by")
			echo "  $id  In Progress -> In Review  (asserted by --landed-by: ${ref:-no ref given})" >&2
		else
			echo "  $id  In Progress -> In Review" >&2
		fi
		fail=1
	fi
done < <(jq -r '.[] | select(.status == "In Progress") | .id' <<<"$issues" | sort -u)

[[ "$fail" = 0 ]] && echo "landed-check: no In Progress issue has commits on main"
exit "$fail"
