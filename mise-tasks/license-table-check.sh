#!/usr/bin/env bash
#MISE description="Gate: every adopted tool's license row is resolved — the release precondition CONTRIBUTING.md states in prose, as a predicate"
#
# CONTRIBUTING.md's license table ends with "Confirm each _to confirm_ entry
# before that tool is adopted in a shipped release." That sentence is a release
# precondition, and it had no runnable check: three of five rows carried
# `_to confirm_` in both columns and nothing failed. A rule without its mechanism
# is half a change (AGENTS.md, non-negotiable rule 2), so this is the other half.
#
# The table is the data and this is only the assertion over it — the verdicts are
# NOT restated here. A second copy would be a second authority for one fact, and
# the two would drift.
#
# Deliberately narrow. It judges whether a row is *resolved*, never whether the
# recorded license is *correct*: correctness is a human reading an upstream
# LICENSE file, which no exit code can stand in for. What the gate can prove is
# that nobody shipped while the question was still open.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT empty-table-passes|s/^if \[\[ "\$rows" -eq 0 \]\]; then$/if false; then/|a table with no rows is a failure

set -uo pipefail

DOC="${1:-CONTRIBUTING.md}"

if [[ ! -r "$DOC" ]]; then
	echo "::error:: license-table-check: cannot read $DOC" >&2
	exit 1
fi

# The compatibility column is a closed set. An unrecognised glyph is a failure
# rather than a pass, because "some other marker" is exactly how an unresolved
# row would slip through a check that only looked for the literal placeholder.
readonly YES='✅'
readonly NO='❌'

fail=0
rows=0

# Read the table between its heading and the next blank-line-terminated block.
# Rows are `| cell | cell | cell | cell |`; the header and the `---` separator
# are skipped by shape, not by line number, so inserting a row cannot shift the
# parse.
while IFS= read -r line; do
	case "$line" in
	'|'*'|') ;;
	*) continue ;;
	esac
	case "$line" in
	*'---'*) continue ;;
	esac

	tool=$(printf '%s' "$line" | cut -d'|' -f2 | sed 's/^ *//; s/ *$//')
	license=$(printf '%s' "$line" | cut -d'|' -f4 | sed 's/^ *//; s/ *$//')
	compat=$(printf '%s' "$line" | cut -d'|' -f5 | sed 's/^ *//; s/ *$//')

	# The header row names the columns rather than a tool.
	[[ "$tool" = "Tool" ]] && continue
	[[ -z "$tool" ]] && continue

	rows=$((rows + 1))

	if [[ -z "$license" ]] || [[ "$license" != "${license#*to confirm}" ]]; then
		[[ "$fail" = 0 ]] && echo "::error:: license-table-check: a row's license is unresolved. Read the upstream LICENSE file and record the SPDX id:" >&2
		printf '  %s — license is %s\n' "$tool" "${license:-empty}" >&2
		fail=1
		continue
	fi

	if [[ "$compat" != "$YES" ]] && [[ "$compat" != "$NO" ]]; then
		[[ "$fail" = 0 ]] && echo "::error:: license-table-check: a row's Apache-2.0 verdict is unresolved or outside the closed set ($YES / $NO):" >&2
		printf '  %s — verdict is %s\n' "$tool" "${compat:-empty}" >&2
		fail=1
	fi
done <"$DOC"

if [[ "$rows" -eq 0 ]]; then
	# A table that parses to zero rows passes every per-row assertion vacuously,
	# which is the false green this branch exists to kill: a renamed heading or a
	# reformatted table would otherwise read as "all rows resolved".
	echo "::error:: license-table-check: no license rows found in $DOC — the table moved or its shape changed" >&2
	exit 1
fi

[[ "$fail" = 0 ]] && echo "license-table-check: $rows adopted-tool rows, every license and verdict resolved"
exit "$fail"
