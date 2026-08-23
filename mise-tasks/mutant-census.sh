#!/usr/bin/env bash
#MISE description="Gate: every gate in the tree is either mutation-enforced or carries a filed exemption (CLOUD-480)"
#
# CLOUD-418 built `mutant` and seeded `$MUTANT_GATES` with five names. That set
# holds one property and misses its complement: a gate IN the list with no
# `#MUTANT` row fails, so coverage cannot be silently zero for anything enforced
# — but a gate that was NEVER LISTED is invisible, and the list and the tree
# drift apart the moment somebody adds a gate. Measured when this ran first:
# fifty-eight gates outside the set, six of which already carried `#MUTANT` rows
# that no run had ever applied. A declaration nothing enforces reads as coverage,
# which is the defect CLOUD-418 exists to refuse, one level up.
#
# So this is the sensor on the set, in both directions — the shape
# `ci-local-parity` uses for `$CI_REQUIRED_CHECKS`:
#
#   uncovered            a gate in the tree that is neither declared nor exempt
#   names-no-subject     a name in $MUTANT_GATES resolving to no gate at all
#   declared-and-exempt  both at once, so the exemption's reason is a dead letter
#   exempt-unfiled       an exemption with no issue key or no reason
#
# WHAT COUNTS AS A GATE IS DERIVED, NEVER A SECOND LIST. `mise-tasks/` holds
# programs that refuse and programs that measure, launch, record or report, and
# only the first kind owes a mutation. The discriminator is the program's OWN
# `#MISE description`: `Gate…` for a task that decides, and `hook body` for the
# `PreToolUse`/`Stop` bodies, which decide by emitting a deny. That is the same
# string `mise tasks` shows a human, so a task cannot quietly leave the census by
# being renamed — it would have to stop describing itself as a gate, which is a
# visible edit to the line every reader sees. A hand-typed roster here would be
# the drifting second authority this issue exists to remove.
#
# `policy/*.rego` is in scope unconditionally. CLOUD-843's campaign moves
# predicates out of `mise-tasks/` and into modules, and a migration that could
# not be counted here would shrink the enforced set while reporting the census
# going down — the false progress that campaign exists to make visible. A module
# has no `#MISE` line to read, and every module in this tree is a policy that
# decides, so there is nothing to discriminate.
#
# AN EXEMPTION IS A FILED ROW, and that is the whole difference between this and
# a `TODO`. `#MUTANT-EXEMPT <CLOUD-key>|<why>` lives beside the code it excuses,
# for the reason the `#MUTANT` rows do — a declaration in a second file is a
# second authority that drifts — and it must name an issue, so the gap has an
# owner and a place to be closed rather than a comment nobody re-reads.
#
# Output is pointer-only per non-negotiable rule 4: the gate and the verdict,
# never a line of the program or the reason's prose.
#
# Exit 0 the census is closed / 1 it is not / 2 could not look.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT uncovered-gate-passes|s/^\t\[\[ "\$in_set" = 1 \]\]/\ttrue/|| report "\$src" "uncovered"$/\ttrue/|a gate the set omits is uncovered, and named

set -euo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

fail_input() {
	echo "::error:: mutant-census: $*" >&2
	exit 2
}

gates="${MUTANT_GATES:-}"
[[ -n "$gates" ]] ||
	fail_input "MUTANT_GATES is unset — run this through \`mise run mutant-census\`, which is where the enforced set is declared. An empty set would make every gate in the tree read as uncovered, which is a verdict about the environment rather than about the tree."

declared=" ${gates//,/ } "

violations=0
report() { # pointer-only (rule 4): the subject then the verdict id
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

# THE CLASSIFIER, and it is one `sed` over the program's own description rather
# than a pattern over its name. `*-check` and `*-guard` cover most of the tree
# and neither covers `doctor`, `mutant`, `semver`, `verified` or `tree-clean`,
# every one of which refuses.
is_gate() {
	local desc
	desc=$(sed -n 's/^#MISE description="\(.*\)"$/\1/p' "$1" | head -n1)
	[[ "$desc" == Gate* ]] || [[ "$desc" == *"hook body"* ]]
}

subjects=""
for src in mise-tasks/*.sh; do
	[[ -f "$src" ]] || continue
	is_gate "$src" || continue
	subjects+="${src#mise-tasks/}
"
done
subjects="${subjects//.sh/}"
for src in policy/*.rego; do
	[[ -f "$src" ]] || continue
	name="${src#policy/}"
	subjects+="${name%.rego}
"
done

# A tree that resolved no gate at all is could-not-look, never a closed census:
# the classifier failing silently would report perfect coverage over nothing,
# which is `mutant`'s own anti-vacuity term one level out.
[[ -n "${subjects//[[:space:]]/}" ]] ||
	fail_input "no gate resolved in mise-tasks/ or policy/ — the census cannot be closed over an empty set, and a pass here would report coverage of nothing"

census=0
for gate in $subjects; do
	census=$((census + 1))
	src="mise-tasks/$gate.sh"
	[[ -f "$src" ]] || src="policy/$gate.rego"
	exempt=$(sed -n 's/^#MUTANT-EXEMPT //p' "$src" | head -n1)
	in_set=0
	[[ "$declared" == *" $gate "* ]] && in_set=1

	if [[ -n "$exempt" ]]; then
		# The reason is READ but never echoed: the verdict names the row's
		# defect, and the prose is in the file the pointer points at.
		key="${exempt%%|*}"
		why="${exempt#*|}"
		if [[ ! "$key" =~ ^CLOUD-[0-9]+$ ]] || [[ -z "${why//[[:space:]]/}" ]] || [[ "$why" == "$exempt" ]]; then
			report "$src" "exempt-unfiled"
			continue
		fi
		[[ "$in_set" = 0 ]] || report "$src" "declared-and-exempt"
		continue
	fi

	[[ "$in_set" = 1 ]] || report "$src" "uncovered"
done

# THE REVERSE DIRECTION. `mutant` already answers `no-such-gate` for a name that
# resolves to nothing, but only when somebody runs it — and it is deliberately
# off the landing path, so a rename that stranded a name could sit unread. This
# is the cheap half and it runs wherever this gate does.
for gate in ${gates//,/ }; do
	[[ -f "mise-tasks/$gate.sh" ]] || [[ -f "policy/$gate.rego" ]] ||
		report "$gate" "names-no-subject"
done

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: mutant-census: $violations violation(s) over $census gate(s) — a gate outside \$MUTANT_GATES is covered by nothing stronger than \"its suite is green\", which CLOUD-418 measured as insufficient four times. Declare a #MUTANT row and add the name, or carry a #MUTANT-EXEMPT naming the issue that owns the gap." >&2
	exit 1
fi
echo "mutant-census: $census gate(s), every one declared in \$MUTANT_GATES or exempt by a filed row"
