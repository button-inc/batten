#!/usr/bin/env bash
#MISE description="Gate: .coderabbit.yaml still carries the keys the review lifecycle depends on (pointer-only)"
#
# CLOUD-860, and the missing half of CLOUD-847. That row landed `.coderabbit.yaml`
# and measured every key in it; nothing then held the file to those readings, so
# a rule shipped without a mechanism — the shape non-negotiable rule 2 names.
#
# THE THREE KEYS ARE NOT A STYLE PREFERENCE, they are what the lifecycle rests on:
#
#   request_changes_workflow  findings arrive as a formal CHANGES_REQUESTED review,
#                             so `reviewDecision` carries an answer. Off, the bot
#                             only COMMENTS and the decision stays null.
#   auto_review.drafts        the draft phase is the free phase (every job in
#                             ci.yml is `if: draft == false`). Off, nothing reviews
#                             it, and the review can only arrive after the ready —
#                             which is the whole defect CLOUD-847 measured.
#   tools.gitleaks.enabled    the ONLY secret scanning a draft gets, for the same
#                             reason: `mise run ci` does not run on drafts. The
#                             other linters are deliberately off because our gates
#                             already run them; this one is deliberately kept.
#
# WHY THE FAILURE IS WORTH A GATE RATHER THAN A COMMENT. Flipping `drafts` back is
# a one-line diff, and its symptom is silence: reviews stop happening, which looks
# exactly like nobody having pushed. The gate that consumes the config would then
# refuse every PR for want of a review the config quietly stopped producing, and
# the visible failure would be the gate rather than the cause.
#
# ABSENT IS NOT PASSING for the first two, and that asymmetry is the point: a key
# nobody wrote and a key someone deleted are the same file, and both leave the
# default in force — which is the value this gate exists to refuse. `gitleaks` is
# the inverse, because its default IS enabled: only an explicit `false` is a
# violation there, so absence passes.
#
# Pointer-only per non-negotiable rule 4: `path:line key=value` and a count, never
# a byte of the file. A config can carry instructions and paths, and a gate that
# echoed them would put them in every CI log.
#
# Exit 0 every required key holds / 2 a key is missing or flipped. No fail-open
# arm, unlike a gate that reads GitHub: the input is a tracked file in this
# checkout, so "could not look" means the file is gone, which is itself the
# violation this refuses.
#
# The mutation drops the empty-file guard, so a file with no keys reports zero
# violations — the vacuous pass this gate is shaped to avoid, and only the
# empty-fixture case can catch it.
#MUTANT empty-file-is-a-pass|s/if \[\[ "\$keys" -eq 0 \]\]/if false/|a file with no keys must not read as compliant
set -euo pipefail

CFG="${1:-.coderabbit.yaml}"

if [[ ! -f "$CFG" ]]; then
	echo "::error:: coderabbit-config-check: $CFG is absent — the review lifecycle has no configuration to rest on" >&2
	exit 2
fi

violations=0
report() { # $1 = line (0 when the key is absent), $2 = pointer
	echo "$CFG:$1 $2" >&2
	violations=$((violations + 1))
}

# A key line at any indentation, reported with its line number. The file is ours
# and its shape is reviewed; this reads the key rather than the tree, which is
# what keeps the gate to one awk pass and no YAML dependency.
key_line() { # $1 = key name -> "line<TAB>value", empty when absent
	awk -v key="$1" '
		$0 ~ "^[[:space:]]*#" { next }
		{
			pattern = "^[[:space:]]*" key ":[[:space:]]*"
			if ($0 ~ pattern) {
				value = $0
				sub(pattern, "", value)
				sub("[[:space:]]*#.*$", "", value)
				sub("[[:space:]]+$", "", value)
				print NR "\t" value
				exit
			}
		}
	' "$CFG"
}

# `enabled:` appears once per tool, so this one is scoped: find the tool, then read
# the first `enabled:` inside its block. Reading it unscoped would answer about
# whichever tool happened to come first in the file.
tool_enabled() { # $1 = tool name -> "line<TAB>value", empty when the tool is absent
	awk -v tool="$1" '
		$0 ~ "^[[:space:]]*#" { next }
		!seen && $0 ~ ("^[[:space:]]*" tool ":[[:space:]]*$") { seen = 1; next }
		seen && $0 ~ "^[[:space:]]*enabled:[[:space:]]*" {
			value = $0
			sub("^[[:space:]]*enabled:[[:space:]]*", "", value)
			sub("[[:space:]]*#.*$", "", value)
			sub("[[:space:]]+$", "", value)
			print NR "\t" value
			exit
		}
		seen && $0 ~ "^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*$" { exit }
	' "$CFG"
}

# The vacuity guard, and the reason it is first: every check below is an assertion
# ABOUT a key, so a file carrying none of them satisfies all of them by having
# nothing to judge. Counting real keys turns "no violations found" back into a
# statement about a file that was actually read.
keys=$(grep -cE '^[[:space:]]*[A-Za-z0-9_-]+:' "$CFG" || true)
if [[ "$keys" -eq 0 ]]; then
	echo "::error:: coderabbit-config-check: $CFG carries no keys at all, so every assertion below would pass vacuously" >&2
	exit 2
fi

require_true() { # $1 = key name
	local hit line value
	hit=$(key_line "$1")
	if [[ -z "$hit" ]]; then
		report 0 "$1 absent (default is in force)"
		return
	fi
	line=${hit%%	*}
	value=${hit#*	}
	[[ "$value" = "true" ]] || report "$line" "$1=$value (want true)"
}

require_true "request_changes_workflow"
require_true "drafts"

# The inverse arm: gitleaks defaults to enabled, so absence is compliant and only
# an explicit `false` is the violation.
hit=$(tool_enabled "gitleaks")
if [[ -n "$hit" ]]; then
	line=${hit%%	*}
	value=${hit#*	}
	[[ "$value" != "false" ]] || report "$line" "tools.gitleaks.enabled=false (drafts would have no secret scanning)"
fi

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: coderabbit-config-check: $violations violation(s) in $CFG — see CLOUD-847 for what each key was measured to do" >&2
	exit 2
fi
echo "coderabbit-config-check: $CFG holds the three keys the review lifecycle depends on"
