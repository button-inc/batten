#!/usr/bin/env bash
#MISE description="Gate: rust.yml's paths filter selects every input its jobs read, and does not select a docs-only diff (CLOUD-398)"
#
# `rust.yml` carries a workflow-level `paths:` filter so a diff that cannot change
# its four verdicts creates no check run at all — ABSENT, which
# `CI_ABSENT_OK_CHECKS` accepts, rather than `skipped`, which `checks-green` reads
# as no answer and `land` polls forever on.
#
# THE FAILURE THIS EXISTS FOR IS SILENT IN THE DANGEROUS DIRECTION. A filter that
# selects too widely costs money and is obvious in the bill. A filter that selects
# too NARROWLY does not fail: the four jobs are simply absent, `checks-green`
# accepts absent by design, `land` merges, and a `windows` regression reaches
# `main` with every required check green. Nothing anywhere else in this repository
# would notice. That asymmetry is why the glob ships with a gate over its own
# honesty rather than with a comment claiming it is right — the shape CLOUD-224
# set for gate globs, applied to the one glob that decides whether a job runs at
# all.
#
# WHAT IS AND IS NOT DECIDABLE HERE. "Which files does a job read" is not
# computable from committed text — a task can shell out to anything. So this does
# not try to derive the list. It fixes the CLAIMS the filter makes, as probes, and
# decides whether the committed filter honours them: the paths a change to which
# must re-run these jobs, and the paths a change to which must not. Adding a job
# with a new input means adding its probe here, in the same commit, which is the
# same bargain `step-receipt`'s spec table makes.
#
# Output is a pointer per non-negotiable 4: the probe path and the verdict that
# disagreed. Never the diff, never a file's contents.
#
# Exit 0 the filter honours every probe / 1 one is wrong / 2 could not look.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

readonly WORKFLOW="${1:-.github/workflows/rust.yml}"

if [ ! -f "$WORKFLOW" ]; then
	echo "::error:: rust-paths-check: $WORKFLOW not found, so there is no filter to judge." >&2
	exit 2
fi

# The `paths:` list, as committed. A block sequence under `paths:` at the
# `pull_request` level; each entry is a quoted or bare scalar on its own line.
# Read with awk rather than a YAML parser for the reason `ci-tools-check` gives:
# the shape is fixed by this repository's own file and a parser is a dependency
# this gate does not otherwise need.
patterns=$(
	awk '
		/^[ \t]*paths:[ \t]*$/ { inpaths = 1; next }
		inpaths && /^[ \t]*-[ \t]*/ {
			line = $0
			sub(/^[ \t]*-[ \t]*/, "", line)
			gsub(/^"|"$/, "", line)
			gsub(/^'"'"'|'"'"'$/, "", line)
			if (line != "") print line
			next
		}
		inpaths { inpaths = 0 }
	' "$WORKFLOW"
)

# ANTI-VACUITY, and it is the whole reason this is exit 2 rather than a pass. A
# workflow with no `paths:` block runs on every PR — expensive, but SAFE — and a
# gate that read that as "every probe honoured" would be reporting on a filter
# that does not exist. `mise-action-floor` refuses the same way when no pin of
# its subject is present.
if [ -z "${patterns//[[:space:]]/}" ]; then
	echo "::error:: rust-paths-check: $WORKFLOW declares no pull_request \`paths:\` entries, so there is no filter here to judge." >&2
	exit 2
fi

# GitHub's filter syntax, restricted to the three shapes this repository uses,
# and REFUSING anything else rather than guessing. A pattern this cannot evaluate
# is a pattern whose verdict below would be fiction: `?`, `[abc]`, a `*` in the
# middle and a leading `!` negation all change selection in ways a prefix test
# gets wrong, and getting one wrong here is exactly the silent false-absent this
# gate exists to stop.
matches() { # $1 = pattern, $2 = candidate path
	local pattern="$1" path="$2" prefix
	# A shape whose selection a prefix test gets wrong. Refused rather than
	# guessed: a wrong answer here is the silent false-absent this gate exists to
	# stop, and an operator adding such a pattern should have to extend the
	# matcher in the same commit.
	refuse() {
		echo "::error:: rust-paths-check: $WORKFLOW declares the pattern '$pattern', whose selection this gate cannot decide. Extend the matcher in the same commit as the pattern." >&2
		exit 2
	}
	case "$pattern" in
	*'!'* | *'?'* | *'['*) refuse ;;
	esac

	# The trailing star, stripped once. `**` first, so `crates/**` yields
	# `crates/` rather than `crates/*` — and whichever branch ran, a `*` LEFT in
	# the prefix is a star somewhere other than the end, which this cannot decide.
	prefix="${pattern%'**'}"
	if [ "$prefix" = "$pattern" ]; then prefix="${pattern%'*'}"; fi
	if [ "$prefix" = "$pattern" ]; then
		# No trailing star at all: a literal path, and any star in it is a shape
		# this does not evaluate.
		case "$pattern" in *'*'*) refuse ;; esac
		[ "$path" = "$pattern" ]
		return
	fi
	case "$prefix" in *'*'*) refuse ;; esac
	# The empty prefix is its own case, and it is not pedantry: `**` alone strips
	# to nothing, so the `!=` below would read "unchanged, therefore no match" and
	# a filter selecting the entire repository would pass this gate as narrow.
	# Caught by the docs-only probe on its first run.
	[ -z "$prefix" ] || [ "${path#"$prefix"}" != "$path" ]
}

selects() { # $1 = candidate path — 0 when some pattern selects it
	local path="$1" pattern
	while IFS= read -r pattern; do
		[ -n "$pattern" ] || continue
		if matches "$pattern" "$path"; then return 0; fi
	done <<<"$patterns"
	return 1
}

# The declarations sit at column 0 rather than beside the loops they corrupt:
# `mutant` reads them with `sed -n 's/^#MUTANT //p'`, and `shfmt` reindents any
# comment inside a block. The scripts carry no `|`, because the declaration
# grammar is three pipe-separated fields.
#MUTANT narrow-filter-passes|s@^\tif ! selects "\$probe"; then$@\tif false; then@|dropping mise.toml is refused
#MUTANT wide-filter-passes|s@^\tif selects "\$probe"; then$@\tif false; then@|a whole-repository glob is refused
status=0

# MUST SELECT: an input a change to which can move one of the four verdicts.
# `crates/**` and the two cargo manifests are what they compile; `rust-toolchain`
# is the compiler they compile with; `deny.toml` is the policy `cargo deny`
# decides from; `mise.toml` and `mise.lock` define and pin the `mise run` tasks
# the jobs actually invoke, which is the input a filter written from "the Rust
# tree" is most likely to miss.
for probe in \
	crates/batten/src/lib.rs \
	Cargo.toml \
	Cargo.lock \
	rust-toolchain.toml \
	deny.toml \
	mise.toml \
	mise.lock \
	.github/workflows/rust.yml; do
	if ! selects "$probe"; then
		echo "::error:: $WORKFLOW's paths filter does not select '$probe', so a change to it would leave these jobs absent and \`checks-green\` would accept the run without their verdict." >&2
		status=1
	fi
done

# MUST NOT SELECT: a diff these jobs cannot be affected by. This is the half that
# pays for the split, and the half that erodes silently — every widening of the
# filter is invisible except as a bill.
for probe in \
	README.md \
	AGENTS.md \
	.claude/rules/rust.md \
	.serena/memories/core.md; do
	if selects "$probe"; then
		echo "::error:: $WORKFLOW's paths filter selects '$probe', which no job here reads, so a docs-only diff pays for all four jobs." >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "rust-paths-check: $WORKFLOW's paths filter selects every declared input and no docs-only path"
fi
exit "$status"
