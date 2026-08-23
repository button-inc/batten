#!/usr/bin/env bash
#MISE description="Gate: hk.pkl's batten-check glob covers every path batten.toml makes an input — a pure function of the two committed files"
#
# CLOUD-224. `batten-check` used to carry no glob at all, on the reasoning that
# any file can carry a violation, so `cargo run -p batten -- check` rebuilt the
# engine on every commit whatever it touched. Giving it a glob is what makes a
# docs-only commit cheap; the cost of a glob is that the step's trigger is now a
# SECOND authority over a set `batten.toml` already defines, and a second
# authority narrows silently.
#
# The failure that would produce is the one the whole gate model exists to
# prevent: add a `[[rule]]` whose glob names a path outside the list, and the
# gate simply stops running for commits that touch only that path. Nothing goes
# red. `hk check --all` still covers it in CI, so the symptom is a rule that
# quietly does not gate a branch — feedback deleted, verdict preserved.
#
# So this asserts the containment directly, of the committed bytes. What
# `batten check` reads is three things (crates/batten/src/lib.rs, run_check_with):
#
#   1. every `[[rule]]`, over that rule's own `glob`
#   2. `budget::measure_all` — `[budget.instructions] files` and every
#      `[[budget.instructions.embedded]] path`. A declared budget is a gate under
#      `check`, not only under `policy budget` (CLOUD-50), which is why AGENTS.md
#      is an input and "Markdown cannot change this verdict" is false.
#   3. `defects::gate`, which reads a ledger path only when [defects] is declared
#
# 1 and 2 are what this gate reads out of batten.toml. 3 declares no path in this
# repository today; a [defects] table that names one is the case to extend here.
#
# NOT checked, and not checkable by a glob at all: a `ratchet` rule's verdict
# also moves when its `base` (origin/main) moves, with no file in this repository
# changing. That is a property of the world, and `hk check --all` in CI is what
# covers it — the same split `lock-complete`/`lock-currency` documents.
#
# Output is a pointer, never a payload (non-negotiable 4): the uncovered glob and
# the file that demands it.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT uncovered-glob-passes|s/^\tif \[\[ "\$ok" = 0 \]\]; then$/\tif false; then/|absent from the list is caught

set -euo pipefail

# Both inputs are ARGUMENTS defaulting to the real files, for the same reason
# `ci-tools-check` takes both of its: the decision is the part worth testing, and
# it only tests if the suite can point it at fixtures carrying drift the real
# tree must never have.
cd "$(git rev-parse --show-toplevel)"

readonly CONFIG="${1:-batten.toml}"
readonly HOOKS="${2:-hk.pkl}"

for f in "$CONFIG" "$HOOKS"; do
	if [[ ! -f "$f" ]]; then
		echo "::error:: batten-glob-check: $f not found" >&2
		exit 2
	fi
done

# --- what batten.toml makes an input ---------------------------------------
#
# Three shapes, one per table that can name a path. Each prints `<glob>\t<line>`
# so a finding can point at the line that demands it.
#
# `[[rule]]` blocks: the `glob` key. A rule with no `glob` selects nothing extra.
# `[budget.instructions]`: `files = [...]`, a one-line array in this config and
# gated as such — a multi-line array would need continuation tracking, and the
# `no-budget-entries` guard below is what notices if one ever appears.
# `[[budget.instructions.embedded]]`: the `path` key.
required=$(awk '
	/^\[\[rule\]\]/                     { table = "rule"; next }
	/^\[budget\.instructions\]/         { table = "budget"; next }
	/^\[\[budget\.instructions\.embedded\]\]/ { table = "embedded"; next }
	/^\[/                               { table = ""; next }
	table == "rule" && /^glob = / {
		line = $0; sub(/^glob = /, "", line); gsub(/"/, "", line)
		print line "\t" NR
		next
	}
	table == "embedded" && /^path = / {
		line = $0; sub(/^path = /, "", line); gsub(/"/, "", line)
		print line "\t" NR
		next
	}
	table == "budget" && /^files = \[/ {
		line = $0
		sub(/^files = \[/, "", line); sub(/\].*$/, "", line)
		n = split(line, parts, ",")
		for (i = 1; i <= n; i++) {
			gsub(/^[ \t]+|[ \t]+$/, "", parts[i])
			gsub(/"/, "", parts[i])
			if (parts[i] != "") print parts[i] "\t" NR
		}
		next
	}
' "$CONFIG")

# A config this gate can parse nothing out of is not a config with no inputs —
# it is a parse that failed, and passing on it would be the vacuous green a
# containment check can most easily produce.
if [[ -z "$required" ]]; then
	echo "::error:: batten-glob-check: parsed no rule glob or budget path out of $CONFIG — a config batten check reads nothing from is not a thing this repo has" >&2
	exit 2
fi

# --- what hk.pkl's batten-check step selects --------------------------------
#
# The `glob = List(...)` belonging to the `["batten-check"]` step, and only that
# one: the file carries a dozen others. Bounded by the step's own header and the
# next step's, so a later step's list cannot be read as this step's.
covered=$(awk '
	/^  \["batten-check"\]/ { in_step = 1; next }
	in_step && /^  \["/     { in_step = 0 }
	in_step && /glob =/     { in_glob = 1 }
	# A COMMENT INSIDE THE LIST IS NOT LIST SYNTAX, and reading it as such made
	# this gate lie. The entries carry a comment each recording which rule made
	# the path an input; one of them contained `(CLOUD-614)`, whose `)` ended the
	# list here — so every entry BELOW it went uncovered and the gate reported
	# four paths that were listed all along. A containment check that mis-parses
	# in the reporting direction is survivable; the same parse silently DROPPING
	# entries from `required` would not be, which is why this skips rather than
	# tries to be clever about the paren.
	in_glob && /^[ \t]*\/\// { next }
	in_glob {
		# One entry per quoted string, however the list is wrapped: pkl format
		# breaks a long List across lines, so neither a one-line nor a
		# one-per-line shape can be assumed.
		rest = $0
		while (match(rest, /"[^"]*"/)) {
			print substr(rest, RSTART + 1, RLENGTH - 2)
			rest = substr(rest, RSTART + RLENGTH)
		}
		if (index($0, ")") > 0) in_glob = 0
	}
' "$HOOKS")

if [[ -z "$covered" ]]; then
	echo "::error:: batten-glob-check: found no \`glob = List(...)\` on the [\"batten-check\"] step in $HOOKS. A glob-less step runs on every commit — which is what CLOUD-224 removed, so its absence is a regression, not a default." >&2
	exit 1
fi

# --- containment ------------------------------------------------------------
#
# Covered means: present verbatim, or subsumed by a `P/**` entry whose prefix the
# required glob starts with. That second clause is the whole reason the list can
# stay short — one `crates/**` stands for `crates/**/*.rs`,
# `crates/batten/tests/**` and `crates/batten/tests/**/*.rs`.
#
# It is deliberately NOT general glob subsumption, which is undecidable in the
# directions that matter and would be a matcher this repo would then have to own.
# A prefix test is the narrow, honest case; anything it cannot prove must be
# listed verbatim, which fails CLOSED — the direction a containment check has to
# fail in.
fail=0
reported=0
while IFS=$'\t' read -r want line; do
	[[ -n "$want" ]] || continue

	ok=0
	while IFS= read -r have; do
		[[ -n "$have" ]] || continue
		if [[ "$have" = "$want" ]]; then
			ok=1
			break
		fi
		case $have in
		*/'**')
			prefix=${have%'**'}
			case $want in
			"$prefix"*)
				ok=1
				break
				;;
			esac
			;;
		esac
	done <<<"$covered"

	if [[ "$ok" = 0 ]]; then
		if [[ "$reported" = 0 ]]; then
			echo "::error:: hk.pkl's batten-check glob does not cover every path batten.toml makes an input, so the gate silently stops running for commits that touch only these (CLOUD-224):" >&2
			reported=1
		fi
		echo "  $CONFIG:$line: \`$want\` — add it to the \`glob = List(...)\` on the [\"batten-check\"] step in $HOOKS" >&2
		fail=1
	fi
done <<<"$required"

if [[ "$fail" = 0 ]]; then
	echo "batten-glob-check: $HOOKS's batten-check glob covers every path $CONFIG makes an input"
fi
exit "$fail"
