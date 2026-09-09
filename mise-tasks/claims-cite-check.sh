#!/usr/bin/env bash
#MISE description="Gate: an ADDED doc comment asserting an absolute about behaviour names somewhere to look"
#
# CLOUD-1703. A plan for that row asserted, of a stricter lease-body parser, that
# "a garbage lease is still takeable — this cannot wedge the fleet." It was false
# in the direction that matters: `authorises` answers `Run` on a `Garbage` reading
# and `turn` answers `Wait`, so an unparseable body is unheld AND uncontested and
# two landers can write one trunk. The claim was never checked, it was load-bearing
# for three further parts designed on top of it, and it survived three rounds of
# review.
#
# ─── THE TELL IS THE MISSING CITATION, AND THAT IS ALL THIS DECIDES ──────────
#
# Every neighbouring claim in that text carried a `file:line`. That one did not,
# because there was no line to cite — the sentence was an inference promoted to a
# fact. So the SIGNATURE of the defect is mechanical even though the defect is not:
# an absolute about behaviour, standing among neighbours that cite, citing nothing.
#
# IT CHECKS FOR A CITATION, NEVER FOR TRUTH. Whether a cited claim is correct is
# not computable and a gate pretending otherwise would be a judge (CLOUD-93), so a
# green run here is not a verdict about correctness — only that a reader was given
# somewhere to look. `ready-cites-check` states the same boundary for the same
# reason and the refusal below says so out loud, so nobody reads a pass as one.
#
# ─── ADDED LINES ONLY, WHICH IS WHAT MAKES IT LANDABLE ───────────────────────
#
# The tree already carries hundreds of correct absolutes written before this rule
# existed. A whole-tree scan would redden every one of them on day one, and a gate
# that must be bypassed to commit is a gate that decides nothing — so this reads
# the delta against the merge-base, the same shape `shell-retirement` takes.
# An existing uncited absolute the delta does not touch is not this gate's finding.
#
# ─── POINTER, NEVER PAYLOAD ──────────────────────────────────────────────────
#
# Rule 4: the output is a count and `path:line`. The sentence itself is never
# echoed — a gate about unsupported claims that quoted them back would put the
# claim in one more place than it already was.
#
# The mutation is the citation test itself. A gate that stopped LOOKING for a
# citation would still print, still exit 0 on a clean delta, and still pass its
# own green-suite check — CLOUD-418's shape, which is why the census refuses a
# gate covered by nothing stronger than that.
#MUTANT citation-never-required|s@if \[\[ "$block" =~ $citation \]\]; then@if true; then@|an added absolute with nothing to look at is refused
set -euo pipefail

base="${1:-}"
if [[ -z "$base" ]]; then
	base="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse HEAD)"
fi

# The absolutes. Deliberately short: each is a word that turns a reading into a
# guarantee, and a longer list would catch prose that is merely emphatic.
#
# BOTH CASES, because a claim is most often the first word of its sentence and the
# lowercase-only form let `/// Never retry ...` through — the shape this gate is
# most likely to meet, missed by the gate written to catch it.
absolutes='\<([Cc]annot|[Nn]ever|[Aa]lways|[Nn]othing)\>'
# What counts as somewhere to look: a source line, a tracked row, or an issue key.
# The backticks are REGEX, not a substitution: the third alternative matches a
# rustdoc intra-doc link, [`symbol`], which is a citation because it resolves.
# shellcheck disable=SC2016
citation='([A-Za-z0-9_./-]+\.(rs|toml|pkl|sh|rego):[0-9]+|CLOUD-[0-9]+|\[`[^`]+`\])'

findings=0

# Tracked files only, for the reason `mutant` stages a tracked tree: an untracked
# scratch file must not be able to satisfy — or trip — a citation rule.
while IFS= read -r file; do
	[[ -f "$file" ]] || continue

	# The added comment lines, with their line numbers in the head file.
	while IFS=: read -r lineno _; do
		[[ -n "$lineno" ]] || continue
		line="$(sed -n "${lineno}p" "$file")"
		# Comments only. Code that says `cannot` is a name, not a claim.
		[[ "$line" =~ ^[[:space:]]*(///|//!|//) ]] || continue
		# MACHINE ROWS ARE DATA, NOT PROSE. `//MUTANT`, `//MUTANT-SUITE`, `carried:`
		# and `ported:` are consumed by other gates, and their fields are slugs and
		# paths rather than sentences — measured on this gate's own first run, which
		# refused `progress-never-published` for containing "never". A row that can be
		# written only in a shape another gate already checks cannot also owe a
		# citation to this one.
		[[ "$line" =~ ^[[:space:]]*//(MUTANT|[[:space:]]*(carried|ported|changed):) ]] && continue
		[[ "$line" =~ $absolutes ]] || continue

		# THE BLOCK, NOT THE LINE. A claim and its citation are routinely a sentence
		# apart, and a per-line rule would force a citation into the middle of every
		# sentence that spans two lines. So the contiguous run of comment lines around
		# this one is the unit, which is also the unit a reader reads.
		start="$lineno"
		while [[ "$start" -gt 1 ]]; do
			prev="$(sed -n "$((start - 1))p" "$file")"
			[[ "$prev" =~ ^[[:space:]]*(///|//!|//) ]] || break
			start=$((start - 1))
		done
		total="$(grep -c '' "$file")"
		end="$lineno"
		while [[ "$end" -lt "$total" ]]; do
			next="$(sed -n "$((end + 1))p" "$file")"
			[[ "$next" =~ ^[[:space:]]*(///|//!|//) ]] || break
			end=$((end + 1))
		done

		block="$(sed -n "${start},${end}p" "$file")"
		if [[ "$block" =~ $citation ]]; then
			continue
		fi
		printf '%s:%s: an absolute about behaviour with nothing to look at\n' "$file" "$lineno"
		findings=$((findings + 1))
	done < <(
		git diff --unified=0 "$base" -- "$file" |
			awk '
        /^@@/ {
          match($0, /\+[0-9]+/)
          n = substr($0, RSTART + 1, RLENGTH - 1)
          next
        }
        /^\+/ && !/^\+\+\+/ { print n ":"; n++ ; next }
        /^-/ { next }
      '
	)
done < <(git diff --name-only --diff-filter=d "$base" -- 'crates/batten/src/*.rs' | while IFS= read -r f; do git ls-files --error-unmatch "$f" >/dev/null 2>&1 && printf '%s\n' "$f"; done)

if [[ "$findings" -gt 0 ]]; then
	printf '\n::error:: claims-cite: %d added claim(s) assert an absolute and cite nothing.\n' "$findings" >&2
	# The backticks are prose: the refusal quotes the three shapes it accepts.
	# shellcheck disable=SC2016
	printf 'Cite a `path.rs:NNN`, a CLOUD key, or a [`symbol`] in the same comment block —\n' >&2
	printf 'or soften the claim to what you actually checked. This decides whether a reader\n' >&2
	printf 'was given somewhere to look, NEVER whether the claim is true: a pass here is not\n' >&2
	printf 'a verdict about correctness.\n' >&2
	exit 1
fi

printf 'claims-cite: no added absolute is uncited\n'
