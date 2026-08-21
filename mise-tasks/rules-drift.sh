#!/usr/bin/env bash
#MISE description="Gate: a value `.claude/rules/*.md` restates still agrees with the mechanism that owns it (CLOUD-506)"
#
# `.claude/rules/toolchain.md` states the rule against restating a value three
# times, in its own words — "the task's own header is the list; a count restated
# here is what went stale twice", "`mise-tasks/` is the authoritative list; don't
# restate a count here, which is how 'three `PreToolUse` hooks' went stale", "the
# settings file is the authoritative list; don't restate its count here" — and
# then restated four values anyway, two of which had drifted:
#
#   toolchain.md   `LAND_MAX_LAPS` (8)          mise-tasks/land.sh   :-2
#   toolchain.md   contract-drift "runs on … `PostToolBatch`"    was never wired
#
# A stale parenthetical in a rules file is not a typo. These files are read by an
# agent that then acts without re-deriving, so it is a false premise delivered
# with the authority of the rule. Being told the runaway lap backstop is 8 where
# the code says 2 changes that judgement by 4x.
#
# WHAT THIS MUST NOT DO, and it is the sharper half of the design: demand that a
# value be restated. The file's rule is the opposite, and a gate pushing toward
# completeness would invert the very discipline it enforces. This fails a claim
# that is PRESENT AND WRONG, never one that is absent — prose stays free to name
# a knob without being made to quote its value.
#
# Two predicates, both cross-file agreements rather than patterns, which is why
# neither can be a `batten.toml` rule today: `forbid` cannot express "agrees
# with", and no rule kind can address a document node (CLOUD-452).
#
# EXIT 0 in agreement / 1 a restated value disagrees. No exit 2: this reads only
# committed text, so there is no "could not look" state to distinguish.
set -euo pipefail

cd "${RULES_DRIFT_ROOT:-$(git rev-parse --show-toplevel)}"
rules="${RULES_DRIFT_RULES:-.claude/rules}"
# THE SECOND PROSE SURFACE (CLOUD-770). `.serena/memories/**` is the largest one
# in the repo and was subject to neither predicate: `memories-check` gates the
# graph's EDGES (CLOUD-183 — `mem:` references resolve, names are addressable)
# and deliberately not content, so a restated value or an unwired `runs on`
# landing in a memory was judged by nothing at all.
#
# It catches zero on the tree as it stands, and that is stated rather than
# hidden: measured 2026-08-20, no memory uses the `` `VAR` (N) `` anchor, and the
# one inverse-form restatement was converted to a pointer in the same change
# rather than gated. The coverage here is PROSPECTIVE, which is the honest claim
# for it — the surface is now walked, so the next one is caught on arrival.
#
# Empty is NOT a failure the way an empty `$rules` is, and the asymmetry is
# deliberate: this repo's rules directory is load-bearing and a missing one means
# a wrong path, whereas a repo with no memory tree is an ordinary consumer.
memories="${RULES_DRIFT_MEMORIES:-.serena/memories}"
settings="${RULES_DRIFT_SETTINGS:-.claude/settings.json}"
tasks="${RULES_DRIFT_TASKS:-mise-tasks}"

violations=0
# Pointer-only (non-negotiable 4): path:line, the name, and the two values.
# Never the sentence — a rules file quotes command lines and env names.
report() {
	echo "::error:: rules-drift: $1" >&2
	violations=$((violations + 1))
}

# A git pathspec `*` crosses `/`, so one pattern per root reaches every depth —
# `.serena/memories/*.md` returns `workflow/board-states.md`. CLOUD-770's issue
# body originally asserted the opposite and was corrected by running it; the
# comment is here so the next reader does not re-derive it from the glob's shape.
files=$(git ls-files -- "$rules/*.md" 2>/dev/null || true)
if [[ -z "$files" ]]; then
	echo "::error:: rules-drift: no tracked markdown under $rules — the path is wrong, and both predicates silently judged nothing." >&2
	exit 1
fi
# Appended, never substituted: an absent memory tree leaves the rules walk exactly
# as it was rather than turning the gate red.
memory_files=$(git ls-files -- "$memories/*.md" 2>/dev/null || true)
[[ -n "$memory_files" ]] && files=$(printf '%s\n%s\n' "$files" "$memory_files")

checked_defaults=0
checked_events=0

# --- predicate 1: a restated env default must match ---------------------------
#
# The construction is `` `VAR` (N) `` — a backticked SHOUTY name immediately
# followed by a parenthesised number. Anchored on that PAIR rather than on the
# name alone, so prose naming a knob without asserting a value is untouched;
# that is the case that keeps the gate from inverting the rule.
#
# The authority is the mechanism's own `${VAR:-N}`. A variable a task reads with
# no default, or one no task reads at all, is not judged: there is nothing to
# disagree with, and inventing a disagreement there would be the completeness
# pressure this must not apply.
while IFS=: read -r file line var claim; do
	[[ -n "$var" ]] || continue
	# `|| true` on every grep in this gate, and it is load-bearing rather than
	# defensive: under `pipefail` a grep that matches nothing fails the pipeline,
	# and under `set -e` that would abort the walk at the first rules file with
	# no restated value — reporting a clean tree by dying quietly.
	actual=$({ grep -rhoE "\\\$\\{$var:-[^}]*\\}" "$tasks" 2>/dev/null || true; } |
		head -n1 | sed -E "s/^\\\$\\{$var:-//; s/\\}$//")
	[[ -n "$actual" ]] || continue
	checked_defaults=$((checked_defaults + 1))
	[[ "$claim" = "$actual" ]] ||
		report "$file:$line ($var) — the rules file says $claim, the mechanism defaults to $actual. The mechanism is the authority; correct the prose, or drop the value and let the reader read it there."
done < <(
	for f in $files; do
		# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
		{ grep -noE '`[A-Z][A-Z0-9_]+` \([0-9]+\)' "$f" || true; } |
			sed -E "s|^([0-9]+):\`([A-Z0-9_]+)\` \(([0-9]+)\)$|$f:\1:\2:\3|"
	done
)

# --- predicate 2: a named hook event must be wired ----------------------------
#
# PARAGRAPH-SCOPED, and keyed on the assertion rather than on the name, which is
# `deferral-check`'s idiom and for the same reason. A rules file must stay able
# to say an event is NOT wired. CLOUD-461 was the motivating instance —
# `contract-drift`'s `PostToolBatch` entry stayed absent until `batten hook`
# grew an advisory channel, and the repo had to be able to write that down —
# and it has since CLOSED, which changes nothing here: the next accepted gap
# needs the same room. What cannot stand is the assertion that a task RUNS on
# an event nothing wires it to. So only a paragraph containing "runs on" is
# judged.
events=$(jq -r '.hooks | keys[]' "$settings" 2>/dev/null || true)
if [[ -z "$events" ]]; then
	echo "::error:: rules-drift: no hook events readable from $settings, so every event named in the rules would report as unwired." >&2
	exit 1
fi

# The harness's event vocabulary. A backticked word outside it is ordinary prose
# — the gate judges event names, and cannot be made to judge every capitalised
# token that happens to sit in a "runs on" paragraph.
known="SessionStart SessionEnd UserPromptSubmit PreToolUse PostToolUse PostToolBatch Stop SubagentStop Notification PreCompact"

for f in $files; do
	# `awk` emits `<line-of-paragraph-start>\t<paragraph on one line>`; a blank
	# line ends a paragraph, matching how these files are written and wrapped.
	while IFS=$'\t' read -r start end para; do
		[[ -n "$para" ]] || continue
		case "$para" in *"runs on"*) ;; *) continue ;; esac
		# SENTENCE-scoped inside the paragraph, and this is the tightening the
		# false-positive case forced. A paragraph that states a wiring often
		# states an accepted gap in the same breath — "it runs on X; the
		# per-batch entry stays absent, and <issue> is why" — so a
		# paragraph-wide check would forbid the repo from recording its own
		# gaps beside the wiring they qualify. Split
		# on `. `; a code span's dots (`mise.toml`, `.claude/settings.json`) carry
		# no following space and survive intact.
		for name in $known; do
			case "$para" in *"\`$name\`"*) ;; *) continue ;; esac
			claims=$({ grep -F 'runs on' <<<"${para//. /$'.\n'}" | grep -cF "\`$name\`" || true; })
			[[ "${claims:-0}" -gt 0 ]] || continue
			checked_events=$((checked_events + 1))
			grep -qxF "$name" <<<"$events" && continue
			# The paragraph carries the claim, but the pointer must name the line
			# a reader has to edit — a bullet list wraps into one paragraph here,
			# and its start can be dozens of lines above the token.
			at=$({ sed -n "${start},${end}p" "$f" | grep -nF "\`$name\`" || true; } |
				head -n1 | cut -d: -f1)
			report "$f:$((start + ${at:-1} - 1)) ($name) — the paragraph says a task runs on \`$name\`, which $settings does not wire at all. Either wire it or say it is absent; \"runs on\" is the claim being checked."
		done
	done < <(awk '
		function flush() { if (buf != "") print start "\t" last "\t" buf; buf = ""; }
		/^[[:space:]]*$/ { flush(); next }
		{ if (buf == "") start = FNR; last = FNR; buf = buf " " $0 }
		END { flush() }
	' "$f")
done

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: rules-drift: $violations restated value(s) disagree with the mechanism that owns them" >&2
	exit 1
fi
echo "rules-drift: $checked_defaults restated default(s) and $checked_events named hook event(s) agree with their mechanisms"
