#!/usr/bin/env bash
#MISE description="Gate: a Ready block's citations name things the tree actually carries (reads get_issue payloads on stdin)"
#
# CLOUD-826. Two gates cross-check a Ready block and between them they leave the
# tree out. `ready-lint` decides the block's clauses against each other — the §6
# bump against the commit type, the §8 blocker prose against a real relation — and
# is a PURE FUNCTION OF THE PAYLOAD. `spec-ref-check` decides that a `CLOUD-N §M`
# citation IN THE TREE names a clause the issue carries. So the tree is checked
# against the issue, and the issue's clauses are checked against each other.
# Nothing checks the issue against the tree.
#
# Measured 2026-08-21 on CLOUD-740, whose §7 demanded two tests CLOUD-780 had
# deleted. Its own reopen header said so in words — "the care notes below …
# describe deleted code and are historical" — and the correction landed in the
# prose ABOVE the Ready block. The block an implementer builds from still demanded
# them, and `ready-lint` exited 0. That is what a missing gate looks like: prose is
# feedforward, only a gate is feedback (non-negotiable rule 2).
#
# ─── WHY THIS IS A SIBLING AND NOT A CLAUSE IN `ready-lint` ──────────────────
#
# `ready-lint`'s purity, not tidiness. `board-write-record` invokes it BY PATH from
# a hook, and says why: "a hook inherits the cwd of the tool call, which is not
# required to be inside this project". Teaching it to read files would make its
# verdict depend on where a hook happened to fire — CLOUD-824's defect class
# arriving in a second place. So the file-reading half lives here, and `ready-lint`
# keeps never opening a file.
#
# ─── THE LIVE BLOCK IS THE LAST ONE, WHICH IS `ready-lint`'S RULE INVERTED ───
#
# A body may carry two Ready blocks — CLOUD-740 carries one headed SUPERSEDED and
# one dated later, kept deliberately so a reader can see which clauses went stale.
# `ready-lint` takes the FIRST opener; this takes the LAST. That is stated rather
# than left implicit because the two gates would otherwise disagree about which
# block they are judging, and a superseded clause carries no obligation.
#
# Measured on CLOUD-740's body, 2026-08-21:
#
#   live block      every_stays_shelled_out_claim_names_its_price   OK
#                   no_second_git_invoker_exists                    OK
#   superseded      a_snapshot_captures_a_dirty_tree_and_nothing_else  fixtures-only
#                   the_worktree_listing_reads_gits_own_attributes     ABSENT
#                   no_second_git_invoker_exists                    OK
#
# ─── THE CORPUS EXCLUDES `tests/fixtures/`, AND THAT IS THE VACUITY GUARD ────
#
# `a_snapshot_captures_a_dirty_tree_and_nothing_else` resolves in exactly one
# place: `tests/fixtures/board-diff-overlap/CLOUD-740.md`, a copy of that row's own
# prose. The test does not exist; a fixture QUOTING the citation does. A gate that
# resolves a citation against a quotation of the citation is vacuous — CLOUD-418's
# exact shape, occurring inside the gate written to prevent it. So a citation
# resolving ONLY under `tests/fixtures/` is a refusal, not a pass.
#
# Tracked files only (`git ls-files`), for the reason `mutant` stages a tracked
# tree: an untracked scratch file must not be able to satisfy a citation.
#
# ─── IT CHECKS EXISTENCE, NEVER RELEVANCE ────────────────────────────────────
#
# Whether a test that exists is the RIGHT test is not computable, and a gate that
# pretended otherwise would be a judge (CLOUD-93). The refusal says so, so a reader
# does not mistake a green run for a verdict about aptness.
#
# A BLOCK CITING NOTHING PASSES, AND THE COUNT IS REPORTED. Vacuity is legitimate
# here — a §7 naming no test symbol is a perfectly good §7 — so the guard is
# visibility rather than refusal: the report states how many citations resolved,
# and a `0` is legible instead of silent.
#
# Output is pointer-only per non-negotiable rule 4: the key, the clause, the
# unresolved token and a count. Never a line of the Ready block and never a line of
# a source file. Sorted, so re-running is byte-stable.
#
# Exit 0 every citation resolves / 1 a citation names nothing in the tree / 2 the
# payload could not be read or the tree could not be resolved — matching
# `ready-lint` and `spec-ref-check` so all three compose under one contract.
#
# ─── A PATH HAS THREE ANSWERS, NOT TWO (CLOUD-920) ───────────────────────────
#
# "Zero-judgement: the file is there or it is not" was one bit where the question
# needs two, and it collapsed in the direction that punishes an author for being
# precise. A §7 obligation naming the suite its own row exists to WRITE cites a
# path that is absent BY DESIGN. Measured over one session's ten-row closure:
# three refusals, CLOUD-359, CLOUD-361 and CLOUD-920 — every one a §7 test
# obligation, not one a stale citation. Precision on this arm was zero, and the
# third row is the row filed to fix it. The cheapest way to pass was to stop
# naming the file, which is the opposite of what CLOUD-826 wanted.
#
# So: resolves / refused / PROSPECTIVE, the fourth value CLOUD-251's split needs
# here — not "is", "is not" or "could not look", but "not yet, by design".
#
# ─── WHICH MECHANISM DRAWS THE LINE, AND WHY THE CHEAPER TWO LOST ────────────
#
# CLOUD-920 §2 named three candidates and made the choice this row's. Decided, and
# the rejected options recorded because a later reader will reach for them again:
#
#   REJECTED — the row's own STATUS. "A row not yet In Progress cannot have written
#   its tests" is cheap and already in the payload, and it is wrong for exactly the
#   row that matters: CLOUD-920 was In Progress while its own citation was still
#   prospective, so the rule would refuse the row it exists to fix, at the moment
#   it was being fixed.
#
#   REJECTED AS THE PRIMARY TERM — git history. `--diff-filter=D` genuinely
#   discriminates deleted from never-written, and it is BLIND in the ordinary
#   environment. Measured 2026-08-23 on a web-session clone: it is shallow, and
#   `tests/memory-guard.bats` — deleted by CLOUD-442 — returns nothing, the same
#   answer as a path that never existed. As the primary term it would silently
#   restore CLOUD-826's defect in every web session, which is the one outcome
#   worse than the false positive being fixed.
#
#   CHOSEN — an explicit spelling, with history kept as the corroborating term.
#   A citation the block marks `(new)` is prospective; an unmarked absence is
#   CLOUD-826's refusal, unchanged. It puts the burden on the author, which is the
#   cost, and it keeps the gate a pure function of the payload plus the tree —
#   the property every board gate here holds. History is then asked only to
#   REFUTE a marker (a path deleted in an ancestor was present, so `(new)` is
#   false), never to grant one, so where it cannot look nothing is forgiven that
#   would not have been forgiven anyway.
#
# The marker is matched WITH ITS PATH — "`<path>` (new)" — so one `(new)` written
# elsewhere in a block cannot excuse every citation in it.
#
# A prospective citation is reported on stderr and leaves the exit code unmoved,
# which is `graph-check`'s `note` shape. Reported rather than skipped: skipping is
# CLOUD-826's defect restored, and the count is in the summary line either way.
#
# The mutation admits `tests/fixtures/` back into the corpus, so a citation that
# resolves only against a quotation of itself passes — the vacuity above, restored.
#MUTANT fixtures-satisfy-a-citation|s@:!:tests/fixtures/@:!:tests/no-such-dir/@|resolves only in a fixture and nowhere else
# And the block-selection mutation: read the FIRST opener rather than the last, so
# a superseded clause's stale citations are judged as live obligations.
#MUTANT superseded-block-is-judged|s@tail -n1@head -n1@|the last opener is the live block
# CLOUD-920's two arms, and they mutate in opposite directions. The first drops the
# marker requirement, so every absent path becomes prospective — CLOUD-826's defect
# restored, which is the one thing the fix must not buy.
#MUTANT marker-not-required|s@^		if grep -qF -- "\\`$p\\` (new)" <<<"$block"; then@		if true; then@|an unmarked absent path is still refused
# The second removes the anti-forgery term, so a `(new)` marker on a path that was
# DELETED passes — an author's claim believed over the history that refutes it.
#MUTANT marker-outranks-history|s@^			if \[\[ -n "$history" \]\] .*@			if false; then@|a marker on a deleted path is refused, not believed
set -uo pipefail

# THE ROOT IS `git::repo_root`'S ANSWER, NEVER `--show-toplevel` (CLOUD-824). That
# flag reports the WORKTREE's top level, so from a linked worktree it names a
# different tree than the engine's own repo-root primitive does — which is the
# defect that let a launcher read the wrong authority, or none. The common dir's
# parent is the main checkout either way. Injectable for the suite, the way
# `spec-ref-check` takes `SPEC_REF_ROOT`.
if ! root="${READY_CITES_ROOT:-}" || [[ -z "$root" ]]; then
	if ! common=$(git rev-parse --git-common-dir 2>/dev/null) || [[ -z "$common" ]]; then
		echo "::error:: ready-cites-check: no repository root to scan — this gate reads the tree and must not guess" >&2
		exit 2
	fi
	if ! common=$(cd -- "$common" 2>/dev/null && pwd); then
		echo "::error:: ready-cites-check: the git common directory is not readable, so the tree could not be resolved" >&2
		exit 2
	fi
	root=$(dirname -- "$common")
fi
cd -- "$root" 2>/dev/null || {
	echo "::error:: ready-cites-check: cannot enter $root" >&2
	exit 2
}

# Exit 2 is "I could not read the input", distinct from exit 1 "a citation is
# wrong" — a caller piping the wrong thing must not look like a stale block.
if ! payload=$(cat) || [[ -z "${payload//[[:space:]]/}" ]]; then
	echo "::error:: ready-cites-check: stdin is empty; expected get_issue payload(s)" >&2
	exit 2
fi
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$payload" 2>/dev/null) ||
	! jq -e 'type == "array" and length > 0 and all(.[]; type == "object" and has("description"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: ready-cites-check: stdin is not a get_issue payload (need a description per issue)" >&2
	exit 2
fi

# THE CORPUS: tracked files under crates/ and tests/, minus tests/fixtures/. The
# exclusion is the vacuity guard argued for in the header, not tidiness.
# An array, not a string: the file list is passed as argv to `grep`, and an
# unquoted expansion to get there is a glob over every path the corpus holds. Read
# with a NUL-delimited loop rather than `mapfile`, which is bash 4 and banned here
# (`no-bash4-mapfile`) — and `-z` is what makes a path containing a newline safe.
corpus=()
while IFS= read -r -d '' f; do
	corpus+=("$f")
done < <(git ls-files -z -- 'crates' 'tests' ':!:tests/fixtures/*' 2>/dev/null || true)
if [[ "${#corpus[@]}" -eq 0 ]]; then
	echo "::error:: ready-cites-check: no tracked files under crates/ or tests/ — a citation cannot be resolved against an empty corpus" >&2
	exit 2
fi

# `ready-lint`'s opener set, so the two gates recognise the same thing and differ
# only in WHICH match they take (see the header).
READY_OPENERS='^\*\*Refinement|^#{2,3} +Refinement|^#{2,3} +Ready|^\*\*Definition of [Rr]eady'
# A clause label, in either corpus dialect — `ready-lint`'s `CLAUSE_LABEL`, narrowed
# to the tag we want when a number is interpolated by the caller below.
CLAUSE_ANY='^[[:space:]]*([*-][[:space:]]*)?\*\*[^*]*\((§|clause )[0-9]+\)|^#{2,6}[[:space:]]+[^#]*\((§|clause )[0-9]+\)'
CLAUSE_7='^[[:space:]]*([*-][[:space:]]*)?\*\*[^*]*\((§|clause )7\)|^#{2,6}[[:space:]]+[^#]*\((§|clause )7\)'

findings=0
resolved=0
cited=0
prospective=0
first_finding=1
reports=""
notes=""

# CAN HISTORY BE ASKED WHETHER A PATH ONCE EXISTED? (CLOUD-920.) A shallow clone
# cannot answer, and that is not an edge case: a Claude Code web session clones
# shallow, so this is the ordinary environment. Measured 2026-08-23 on such a
# clone — `git log --diff-filter=D -- tests/memory-guard.bats`, a path retired by
# CLOUD-442, returns NOTHING, indistinguishable from a path that never existed.
#
# That measurement is why history is the CORROBORATING term here rather than the
# discriminating one. It is asked only to REFUTE a `(new)` marker, never to grant
# one, so where it cannot look the marker stands on its own and no absence is
# silently forgiven.
history=""
if [[ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = false ]]; then
	history=1
fi

report() {
	reports="${reports}  $1"$'\n'
	findings=$((findings + 1))
}

# Does a token appear anywhere in the corpus? `grep -F` over the file list, fixed
# strings, and the list is fed by a here-string rather than a pipe so this stays
# out of `pipefail-grep-check`'s shape.
resolves() {
	local needle="$1" files
	files=$(grep -lF -- "$needle" "${corpus[@]}" 2>/dev/null || true)
	[[ -n "$files" ]]
}

while IFS= read -r key; do
	[[ -n "$key" ]] || continue
	body=$(jq -r --arg k "$key" 'map(select((.id // "") == $k)) | .[0].description // ""' <<<"$issues" 2>/dev/null)
	[[ -n "$body" ]] || continue

	# THE LIVE BLOCK IS THE LAST OPENER (header). A body with none is not this
	# gate's business — `ready-lint` already reports `no-ready-block`, and a second
	# gate reporting the same fact is a second authority over one question.
	start=$(grep -niE "$READY_OPENERS" <<<"$body" | tail -n1 | cut -d: -f1 || true)
	[[ -n "$start" ]] || continue
	block=$(tail -n "+$start" <<<"$body")

	# The §7 span: from its clause label to the next clause label of any number, or
	# the end of the block. Bounded on purpose — a greedier span would sweep later
	# sections and read an unrelated backticked symbol as a test obligation.
	s7=$(grep -nE "$CLAUSE_7" <<<"$block" | head -n1 | cut -d: -f1 || true)
	span=""
	if [[ -n "$s7" ]]; then
		rest=$(tail -n "+$((s7 + 1))" <<<"$block")
		next=$(grep -nE "$CLAUSE_ANY" <<<"$rest" | head -n1 | cut -d: -f1 || true)
		if [[ -n "$next" ]]; then
			span=$(sed -n "${s7},$((s7 + next - 1))p" <<<"$block")
		else
			span=$(tail -n "+$s7" <<<"$block")
		fi
	fi

	# (1) CITED TEST NAMES, inside §7 only. A backticked all-lowercase token with
	# THREE OR MORE underscores. The threshold is what makes it decidable: it
	# captures this repository's test-naming shape and excludes ordinary API names
	# (`check_ignore`, `stash_create`, `update_ref` — one underscore each), so a
	# false positive costs a rename rather than a wrong refusal.
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	for tok in $(grep -oE '`[a-z][a-z0-9_]*`' <<<"$span" 2>/dev/null | tr -d '`' | awk -F_ 'NF >= 4' | sort -u); do
		cited=$((cited + 1))
		if resolves "$tok"; then
			resolved=$((resolved + 1))
		else
			report "$key §7 $tok absent-cited-test"
		fi
	done

	# (2) CITED PATHS, anywhere in the live block. A backticked token carrying a `/`
	# and ending in a source extension. THREE OUTCOMES, not two (CLOUD-920).
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	for p in $(grep -oE '`[A-Za-z0-9_./-]+\.(rs|toml|yml|yaml|bats|md|json|pkl|sh|lock|rego)`' <<<"$block" 2>/dev/null | tr -d '`' | grep -F / | sort -u); do
		cited=$((cited + 1))
		if [[ -e "$p" ]]; then
			resolved=$((resolved + 1))
			continue
		fi
		# PROSPECTIVE, and only when the block SAYS SO. `(new)` immediately after the
		# backticked path is the marker; anything else absent stays CLOUD-826's
		# refusal. The marker is matched against the path so a single `(new)`
		# elsewhere in the block cannot excuse every citation in it.
		if grep -qF -- "\`$p\` (new)" <<<"$block"; then
			# THE ANTI-FORGERY TERM. The marker is the author's claim that this file
			# does not exist yet; history is the one place that can contradict it. A
			# path DELETED in an ancestor was present, so `(new)` is false and the
			# citation is the stale obligation CLOUD-826 exists to refuse — marking it
			# must not buy a pass.
			if [[ -n "$history" ]] && [[ -n "$(git log --format=%h --diff-filter=D -1 -- "$p" 2>/dev/null)" ]]; then
				report "$key §1 $p stale-cited-path"
				continue
			fi
			prospective=$((prospective + 1))
			# `note`, not `report`: the exit code is unmoved, and the pointer is still
			# emitted so a prospective citation is legible rather than skipped.
			notes="${notes}  $key §1 $p prospective-cited-path"$'\n'
			continue
		fi
		report "$key §1 $p absent-cited-path"
	done
done < <(jq -r '.[] | .id // empty' <<<"$issues" 2>/dev/null || true)

# NOTES BEFORE THE VERDICT, and on stderr either way: a prospective citation is
# information about a correct block, so it must not be able to change the exit
# code, and it must not be buried under a refusal that came after it.
if [[ -n "$notes" ]]; then
	printf '%s' "$notes" | sort >&2
	if [[ -z "$history" ]]; then
		# THE HONEST LIMIT, stated rather than left to be discovered. In a shallow
		# clone the anti-forgery term above cannot fire, so a `(new)` marker on a
		# genuinely DELETED path reads as prospective — CLOUD-826's direction. The
		# gate says so instead of implying it was checked.
		echo "::notice:: ready-cites-check: $prospective prospective citation(s) above, and this clone is SHALLOW — so \`(new)\` could not be checked against history. A marker on a path that was deleted rather than never written is not detectable here; CI runs against a full clone, where it is." >&2
	fi
fi

if [[ "$findings" -ne 0 ]]; then
	[[ "$first_finding" = 1 ]] && echo "::error:: ready-cites-check: a Ready block cites something the tree does not carry. This checks EXISTENCE, never relevance — whether a test that exists is the right test is not computable (CLOUD-93). A citation resolving only under tests/fixtures/ is refused, because a fixture quoting the citation is not the thing cited:" >&2
	printf '%s' "$reports" | sort >&2
	echo "::error:: ready-cites-check: $findings of $cited citation(s) resolve nothing" >&2
	exit 1
fi
if [[ "$prospective" -gt 0 ]]; then
	echo "ready-cites-check: $resolved of $cited citation(s) resolve against the tree; $prospective prospective"
else
	echo "ready-cites-check: $resolved of $cited citation(s) resolve against the tree"
fi
