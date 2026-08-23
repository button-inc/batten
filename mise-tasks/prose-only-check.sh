#!/usr/bin/env bash
#MISE description="Gate: a branch whose whole diff is comment lines buys a CI matrix no required check can have an opinion about (reads the diff; pointer-only)"
#
# CLOUD-827. Measured 2026-08-21 by doing it: a branch whose entire diff was two
# rewritten sentences of `//!` doc comment in `crates/batten/src/git.rs` went
# through `verify` and was on its way to `gh pr create` + `land` — a full required
# matrix (`ci`, `cross`, `commit-lint`, `zizmor`, `darwin-link`, `semver`, `perf`,
# `windows`, `final`) against a trunk landing every ~16 minutes. What stopped it
# was a human saying "don't you dare waste CI minutes for comments", which is the
# wrong mechanism: a rule that is only prose is feedforward, and the agent HAD the
# rule — it is in AGENTS.md — and still queued the matrix, because every gate it
# consulted said yes.
#
# THE ECONOMY IS ALREADY WRITTEN DOWN, which is what makes this an omission rather
# than a new opinion. AGENTS.md: "Local execution — bash, a build, the whole test
# suite — costs nothing... A CI run costs real minutes." `ci.yml`'s own header
# names the two economies it implements — drafts run nothing, and `main` is not a
# trigger. This is the third: a change CI cannot have an opinion about should ride
# the next change that it can.
#
# WHY THIS IS NOT "COMMENTS ARE FREE", which would be wrong in this repository. A
# comment here can change a verdict: `every_stays_shelled_out_claim_names_its_price`
# scans a module doc for citations, `no_gix_gap_primitive_survives` scans `src/`
# for retired vocabulary, `spec-ref-check` resolves `CLOUD-<n> §N` citations in
# tracked files, `rules-drift` holds restated defaults against their mechanisms.
# Every one of those runs in `verify`, locally, for free. That is precisely why the
# economy HOLDS rather than fails: if a comment change breaks one, the author
# learns before a runner is spent. CI is confirming what was already proved, and on
# a prose-only diff it confirms nothing that could differ.
#
# THE `tests/` CONJUNCT IS WHAT MAKES THE GOOD CASE PASS, and it is the difference
# between pricing batching and obstructing doc work. A change that adds or edits a
# test is not prose-only — so PR #604, a doc rewrite PLUS the gate that enforces
# it, is admitted, while the follow-up carrying only the two sentences is not.
#
# AN UNRECOGNISED EXTENSION COUNTS AS NOT-A-COMMENT, so an unknown file type
# ADMITS the branch. The failure direction is deliberate: this gate spends someone
# else's minutes when it is wrong in one direction and blocks correct work when it
# is wrong in the other, and only the second is unrecoverable by waiting.
#
# WHERE IT RUNS. `land`'s pre-ready set, beside `deferral-check`,
# `filed-here-check` and `closing-key-check` — the three that already refuse a lap
# on grounds other than correctness — and in `verify`'s path, so enforcing it costs
# no runner.
#
# Pointer-only (non-negotiable 4): the changed paths and a count, never a line of
# the diff. A diff is content someone has not published yet.
#
# `BATTEN_PROSE_ONLY_OVERRIDE=1` mints over the refusal and RECORDS WHAT IT
# OVERRODE, the `BATTEN_FILED_HERE_OVERLAP` idiom — for when the prose IS the
# deliverable and cannot wait. The override is worth having only if it leaves a
# trace, so it writes to `$GIT_DIR/batten-receipts/prose-only-overrides.<branch>`
# and prints the same, so a reviewer sees a decision rather than a silence.
#
# MUTATION COVERAGE (CLOUD-418). The first row is the whole predicate: a gate that
# never refuses is the state this repository was in before it existed, and every
# other case in the suite still passes under it. The second and third are the two
# conjuncts, each of which alone would make the gate wrong in a different
# direction.
#MUTANT prose-only-never-refuses|s/^prose_only=1$/prose_only=0/|a comment-only diff with no test change is refused
#MUTANT prose-only-ignores-tests|s/^\ttests\/\*) touched_tests=1 ;;$/\ttests\/*) : ;;/|a comment change plus a test change is admitted
#MUTANT prose-only-unknown-is-comment|s/^\t\*) return 1 ;;$/\t*) return 0 ;;/|an unrecognised extension admits the branch
#MUTANT prose-only-override-unrecorded|s/^\tprintf '%s.n' "\$note" >>"\$record"$/\t:/|the override admits the branch and records which one
set -uo pipefail

BASE="${PROSE_ONLY_BASE:-origin/main}"

# EXIT 0 IS "DO NOT REFUSE", and every could-not-look path takes it. A gate that
# blocked landing because it failed to compute a diff would be the reason work
# cannot proceed, which is a worse defect than the matrix it is trying to save.
if ! git rev-parse --verify -q "$BASE" >/dev/null 2>&1; then
	echo "prose-only-check: no $BASE to diff against — not judged"
	exit 0
fi

# `--diff-filter=d` drops deletions: a removed file has no surviving lines to
# classify, and treating it as prose would let a branch that deletes a module read
# as a comment change.
files=$(git diff --name-only --diff-filter=d "$BASE...HEAD" 2>/dev/null) || {
	echo "prose-only-check: the diff could not be computed — not judged"
	exit 0
}

if [[ -z "${files//[[:space:]]/}" ]]; then
	echo "prose-only-check: no diff against $BASE — nothing to price"
	exit 0
fi

# Per-extension and deliberately narrow. Returning 1 for anything unrecognised is
# the admitting direction, per the header.
is_comment_line() {
	local path="$1" line="$2"
	# Strip the leading +/- and any indentation before classifying: a comment is a
	# comment at any depth, and `git diff --unified=0` still emits the marker.
	local text="${line:1}"
	text="${text#"${text%%[![:space:]]*}"}"
	# A blank line inside an otherwise-prose hunk is whitespace, not code. Counting
	# it as code would make every reflowed comment block read as a code change.
	[[ -n "$text" ]] || return 0
	case "$path" in
	*.md) return 0 ;;
	*.rs)
		# `//`, `///` and `//!` all begin with `//`; block comments are deliberately
		# NOT recognised, because a `/* */` run cannot be classified line-by-line
		# without tracking state, and guessing here fails in the refusing direction.
		[[ "$text" == //* ]]
		;;
	*.sh | *.bash | *.bats | mise-tasks/*)
		# `mise-tasks/` programs carry no extension (CLOUD-865 renamed most to `.sh`,
		# but the pattern stays so a re-added extensionless task is still read).
		[[ "$text" == \#* ]]
		;;
	*) return 1 ;;
	esac
}

touched_tests=0
for f in $files; do
	case "$f" in
	tests/*) touched_tests=1 ;;
	esac
done

# `--unified=0` so only changed lines are emitted: context lines are unchanged by
# definition and classifying them would make a comment edit next to code read as a
# code change.
prose_only=1
noncomment_count=0
current=""
while IFS= read -r line; do
	case "$line" in
	'+++ '*) continue ;;
	'--- '*) continue ;;
	'diff --git '*)
		# `b/<path>` is the post-image name, which is the one `--diff-filter=d`
		# guarantees exists.
		current="${line##*" b/"}"
		continue
		;;
	'@@'*) continue ;;
	'+'* | '-'*)
		[[ -n "$current" ]] || continue
		if ! is_comment_line "$current" "$line"; then
			prose_only=0
			noncomment_count=$((noncomment_count + 1))
		fi
		;;
	esac
done < <(git diff --unified=0 "$BASE...HEAD" 2>/dev/null)

file_count=$(printf '%s\n' "$files" | grep -c . || true)

if [[ "$touched_tests" -eq 1 ]]; then
	echo "prose-only-check: $file_count file(s) changed, including under tests/ — not prose-only"
	exit 0
fi

if [[ "$prose_only" -eq 0 ]]; then
	echo "prose-only-check: $file_count file(s) changed, $noncomment_count non-comment line(s) — not prose-only"
	exit 0
fi

# From here the branch IS prose-only. The override is read at the refusal rather
# than at the top, so the record names a decision that was actually needed.
if [[ -n "${BATTEN_PROSE_ONLY_OVERRIDE:-}" ]]; then
	branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)
	gitdir=$(git rev-parse --git-dir 2>/dev/null || echo .git)
	record="$gitdir/batten-receipts/prose-only-overrides.$branch"
	mkdir -p "$(dirname "$record")" 2>/dev/null || true
	note="prose-only-check: OVERRIDDEN on $branch — $file_count prose-only file(s)"
	printf '%s\n' "$note" >>"$record"
	echo "$note"
	exit 0
fi

{
	echo "::error:: this branch's whole diff is comment lines and no test changed, so a full CI matrix would confirm nothing $file_count file(s):"
	while IFS= read -r f; do
		[[ -n "$f" ]] || continue
		echo "  $f"
	done <<<"$files"
	echo "Put the content on the row that owns it and let the next change to these files carry it, or set BATTEN_PROSE_ONLY_OVERRIDE=1 if the prose is the deliverable and cannot wait — that records which branch used it."
} >&2
exit 2
