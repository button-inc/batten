#!/usr/bin/env bash
#MISE description="Gate: every committed artifact derived from the command surface — completions and man pages — matches what the binary emits (CLOUD-27, CLOUD-69)"
#
# House style §11: completions, man pages and markdown are *derivations* of the
# command spec, "so the shipped binary and the generated docs can never drift."
# A derivation nothing diffs is a copy, and a copy drifts silently — the
# committed script keeps advertising a flag the surface dropped, or misses one it
# gained, and the first person to notice is a user whose tab-completion lies or
# whose man page documents a verb that no longer parses.
#
# DoR §4 names this shape directly: anything derived from the spec is regenerated
# by its generator and diffed byte-for-byte against the committed copy. This is
# that diff.
#
# ONE GATE OVER A TABLE, not one script per artifact. This was `completions-check`
# and it covered a third of what §11 claims; adding a `man-check` beside it would
# have made three near-identical programs (with `schema-check`) differing only in
# a path and an argv. The rows below are the whole difference. `schema-check`
# stays separate on purpose: its inputs are the config TYPES, so hk globs it on
# `config.rs`/`rules.rs`/`severity.rs`, and folding it in here would rebuild and
# diff every completion script on any config edit.
#
# MARKDOWN IS DELIBERATELY ABSENT. The markdown rendering of the surface is the
# published CLI reference, rendered at publish time and never committed
# (CLOUD-171) — there is no second copy to drift from, so there is nothing here
# to diff. `render`'s own tests cover that every format renders, non-emptily.
#
# The regeneration is deliberately the same command `mise run completions` and
# `mise run man` run — via the binary's stdout-only `generate` verb — so a green
# gate is proof that re-running the documented refresh is a no-op, not merely
# that two files happen to agree.
set -euo pipefail

cd "${DERIVED_ROOT:-$(git rev-parse --show-toplevel)}"

# Emit into a scratch dir rather than over the committed files: a gate that
# rewrites the tree it is judging cannot fail twice, and would launder drift
# into a "clean" second run.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

violations=0
report() { # pointer-only (rule 4): file:line rule-id
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

# One row per committed artifact: the path, then the `generate` argv that emits
# it, TAB-separated — a command path contains spaces (`config show`), so a
# space-split row would hand the binary two arguments and document neither.
#
# The man rows come from `mise-tasks/man-pages.sh`, the one authority for which
# pages exist and what each is called, so a verb added to the surface is covered
# here with no edit. `expected` doubles as the set the orphan scan is judged
# against.
rows=()
expected=()
add_row() { # <committed path> <generate argv...>
	local IFS=$'\t'
	rows+=("$*")
	expected+=("$1")
}

for shell in bash zsh fish; do
	add_row "completions/batten.$shell" generate completions --shell "$shell"
done

MAN_PAGES="$(cd "$(dirname "$0")" && pwd)/man-pages.sh"
if [[ ! -x "$MAN_PAGES" ]]; then
	echo "::error:: derived-check: cannot run $MAN_PAGES, so the man page set is unknown. A gate that checks nothing must not report green." >&2
	exit 2
fi
# Told explicitly which tree to read rather than left to re-derive it: this gate
# runs against a scratch fixture as well as against the checkout, and a helper
# that asked git for the top level would be answering about a different tree —
# or, outside a repository, about none.
if ! pages=$(MAN_PAGES_ROOT="$PWD" "$MAN_PAGES"); then
	echo "::error:: derived-check: could not derive the man page list from the surface" >&2
	exit 2
fi
while IFS=$'\t' read -r file path; do
	[[ -n "$file" ]] || continue
	# The root page's path is empty, and `generate man` with no argument is
	# exactly how the root page is asked for — so an empty path contributes no
	# argv token rather than an empty one.
	if [[ -n "$path" ]]; then
		add_row "$file" generate man "$path"
	else
		add_row "$file" generate man
	fi
done <<<"$pages"

# Every artifact is checked before exiting, so one run names every drifted file
# rather than only the first.
for row in "${rows[@]}"; do
	IFS=$'\t' read -r -a argv <<<"$row"
	committed=${argv[0]}
	if [[ ! -f "$committed" ]]; then
		report "$committed:0" "derived-missing"
		continue
	fi
	emitted="$scratch/${committed//\//_}"
	if ! cargo run --quiet -p batten -- "${argv[@]:1}" >"$emitted"; then
		echo "::error:: derived-check: the binary could not emit $committed" >&2
		exit 1
	fi
	# Pointer-only: the gate names the file that drifted, never the diff body —
	# the remedy is always the same one command, so the bytes add nothing.
	cmp -s "$committed" "$emitted" || report "$committed:0" "derived-drift"
done

# The other direction, which a per-artifact diff cannot see: a committed file the
# surface no longer derives. Removing a verb deletes its row from `man-pages` and
# leaves its page on disk, still installable, still documenting a command that no
# longer parses — and every loop above passes, because nothing asked about it.
#
# Read from the filesystem rather than from `git ls-files`: the fixture this gate
# is tested in is a scratch tree, not a checkout, and a gate whose orphan scan is
# inert outside a repository is one whose only failing case is untested.
present=$(find completions man -type f 2>/dev/null | sort || true)
derived=$(printf '%s\n' "${expected[@]}" | sort)
while IFS= read -r orphan; do
	[[ -n "$orphan" ]] || continue
	report "$orphan:0" "derived-orphan"
done <<<"$(comm -23 <(printf '%s\n' "$present") <(printf '%s\n' "$derived"))"

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: derived-check: $violations derived artifact(s) differ from the surface; run 'mise run completions' and 'mise run man'" >&2
	exit 1
fi
echo "derived-check: all ${#rows[@]} committed artifacts match the surface"
