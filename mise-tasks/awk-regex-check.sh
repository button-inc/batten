#!/usr/bin/env bash
#MISE description="Gate: no shell task hands awk a regex through -v, where escape handling is implementation-defined"
#
# A pattern passed through `awk -v` goes through the assignment's escape
# processing before awk ever sees it as a regex, and what that does to a
# backslash is not defined across implementations. gawk strips `\(` to `(` with
# a warning; mawk keeps it. So the same pattern is a literal paren on one
# machine and a capturing group on the other.
#
# This is not theoretical. `ready-lint` matched its §8 label that way. It worked
# on mawk here and, on the gawk runner, matched NOTHING — so the clause that
# exists to catch a blocker claimed without a relation went back to passing
# silently, and three tests that predated the change went red with it. A gate
# that cannot match its own label does not fail; it passes.
#
# The predicate is the USE, not the value: a literal with no backslash is safe
# today and unsafe the moment someone adds one, and a variable's runtime content
# is invisible to any static check. So this flags a `-v` name that the awk
# program then uses as a regex — `~ name` or `match(…, name)` — regardless of
# what the value looks like at the call site.
#
# `-v` for a plain VALUE stays fine, which is most of its use: comparing with
# `==`, printing, arithmetic. Only regex position is judged.
#
# The fix is always the same shape and needs no new tool: let `grep` find what
# the pattern matches and let awk work in literal patterns, or inline the pattern
# in the awk program where no assignment processing happens.
set -euo pipefail

fail=0
report() {
	[[ "$fail" = 0 ]] && echo "::error:: a regex reaches awk through -v, where escape handling is implementation-defined (see mem:toolchain-and-hooks):" >&2
	printf '  %s\n' "$1" >&2
	fail=1
}

while IFS= read -r hit; do
	[[ -n "$hit" ]] || continue
	# -H, not -n alone: grep omits the filename when handed a single path, which
	# silently turns the pointer into "lineno:text" and misreports the location.
	file=${hit%%:*}
	rest=${hit#*:}
	lineno=${rest%%:*}
	text=${rest#*:}

	# Every -v name assigned on this line.
	for name in $(grep -oE '(^|[[:space:]])-v[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' <<<"$text" |
		grep -oE '[A-Za-z_][A-Za-z0-9_]*=' | tr -d '=' | sort -u); do
		# Used in regex position? `$0 ~ name`, `x ~ name`, or match(s, name).
		if grep -qE "~[[:space:]]*$name([^A-Za-z0-9_]|$)" <<<"$text" ||
			grep -qE "match\([^)]*[,[:space:]]$name([^A-Za-z0-9_]|\))" <<<"$text"; then
			report "$file:$lineno: \`$name\` is assigned with -v and used as a regex"
		fi
	done
done < <(git ls-files -z 'mise-tasks/*' '*.sh' 'mise.toml' 2>/dev/null |
	xargs -0 grep -HnI 'awk' 2>/dev/null | grep -- '-v' || true)

[[ "$fail" = 0 ]] && echo "awk-regex-check: no regex reaches awk through -v"
exit "$fail"
