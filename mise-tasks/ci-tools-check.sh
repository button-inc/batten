#!/usr/bin/env bash
#MISE description="Gate: install_args names resolve to real [tools] entries, and no PR workflow runs mise-action without a binding list"
#
# CI installs a NARROW tool set per job (see .github/workflows/ci.yml): the `ci`
# job takes the hk gate's tools, `cross` takes rust, `darwin-link` takes rust +
# zig + cargo-zigbuild. That is the largest single CI speed-up available — every
# job used to install all 18 tools, and zig (17.3s) set the wall clock in three
# jobs that never invoke it.
#
# The cost of narrowing is a second place where tool names are written down, and
# the failure mode is drift: rename or re-pin a tool in mise.toml and the
# install_args list silently keeps the old name. `mise install` does NOT fail on
# an unknown tool name, so the drift surfaces much later as "command not found"
# in whichever step happened to need it — a missing TOOL wearing a missing-STEP
# costume, which is the same class of late, misattributed failure `doctor`
# exists to kill.
#
# This is that rule's mechanism (AGENTS.md non-negotiable 2): a computable
# predicate over the two files, exit 0 or 1. It asserts NAMES resolve, which is
# the half that can rot silently. It deliberately does not try to infer which
# tools a job "should" need — that is a judgement, not a predicate, and the
# comments in ci.yml carry the reasoning.
#
# Output is a pointer, never a payload (non-negotiable 4): the tool name and the
# file it is missing from.
set -uo pipefail

# Both inputs are ARGUMENTS defaulting to the real files, for the same reason
# doctor-check takes `installed` as an argument: the decision is the part worth
# testing, and it only tests if the suite can point it at fixtures carrying
# drift the real tree must never have.
# `|| exit 1` rather than `set -e`: the checks below deliberately let non-zero
# exits through (an empty `grep` is a real outcome here, not a fatal error), so
# this script cannot take -e the way doctor does.
cd "$(git rev-parse --show-toplevel)" || exit 1

readonly WORKFLOW="${1:-.github/workflows/ci.yml}"
readonly CONFIG="${2:-mise.toml}"
# The second pass's input: a DIRECTORY, because absence is the thing a
# single-file gate structurally cannot see.
#
# It defaults to the first argument's own directory rather than to a literal
# path, and that is what keeps the two passes pointed at one tree. A caller
# aiming the gate at a fixture workflow is asking about that fixture; resolving
# the second pass to `.github/workflows` regardless would silently mix a
# fixture's verdict with the committed tree's, which is the one thing a suite
# built on fixtures must not do. With no arguments at all it resolves to
# `.github/workflows`, which is the real question.
readonly WORKFLOW_DIR="${3:-$(dirname "$WORKFLOW")}"
# The policy file the third pass reads, an ARGUMENT for the same reason
# WORKFLOW_DIR is: a caller aiming this at a fixture workflow is asking about
# that fixture, and reading the committed `batten.toml` against it would mix one
# tree's spawns with another's install list — the one thing a suite built on
# fixtures must not do.
readonly POLICY="${4:-batten.toml}"

for f in "$WORKFLOW" "$CONFIG"; do
	if [[ ! -f "$f" ]]; then
		echo "::error:: ci-tools-check: $f not found" >&2
		exit 1
	fi
done

# The [tools] table's keys, as mise sees them: everything from `[tools]` up to
# the next table header, left of the `=`, unquoted. Comments and blanks drop out
# because they carry no bare `key =`.
declared=$(
	awk '
		/^\[tools\]/          { in_tools = 1; next }
		/^\[/                 { in_tools = 0 }
		in_tools && /^[^#]/ {
			eq = index($0, "=")
			if (eq == 0) next
			key = substr($0, 1, eq - 1)
			gsub(/^[ \t]+|[ \t]+$/, "", key)
			gsub(/^"|"$/, "", key)
			if (key != "") print key
		}
	' "$CONFIG"
)

if [[ -z "$declared" ]]; then
	echo "::error:: ci-tools-check: no [tools] entries parsed from $CONFIG" >&2
	exit 1
fi

# Every install_args value in the workflow, flattened to one tool name per line.
# Each list is a one-line plain scalar, which ci.yml states and this relies on:
# a YAML block scalar would need continuation-line tracking, and several tool
# names begin with `aqua:` so they read as new keys under any such heuristic.
requested=$(
	awk '
		/^[ \t]*install_args:/ {
			sub(/^[ \t]*install_args:[ \t]*/, "")
			print
		}
	' "$WORKFLOW" | tr -s '[:blank:]' '\n' | grep -v '^$' | sort -u
)

if [[ -z "$requested" ]]; then
	echo "::error:: ci-tools-check: no install_args lists found in $WORKFLOW — CI would install the whole toolchain in every job" >&2
	exit 1
fi

status=0
count=0
while IFS= read -r tool; do
	count=$((count + 1))
	if ! grep -qxF "$tool" <<<"$declared"; then
		echo "::error:: $WORKFLOW installs '$tool', which is not a [tools] entry in $CONFIG. CI would skip it and fail later as 'command not found'." >&2
		status=1
	fi
done <<<"$requested"

# ---------------------------------------------------------------------------
# THE SECOND DIRECTION, AND WHY THE FIRST ONE COULD NOT ASK IT (CLOUD-812).
#
# Everything above judges the names IN a list. A workflow that declares no list
# at all has no names to judge, so it passes — and that is not a hole in the
# predicate, it is a hole in the trigger: the gate is absence-blind by
# construction, because it was pointed at one file that happened to be compliant.
#
# CLOUD-180 narrowed `ci.yml` and its Done list said so precisely — "per-job
# `install_args` in `ci.yml`, with auto-install off so the lists bind." Measured
# 2026-08-20, `commit-lint.yml` and `zizmor.yml` had never been in that scope and
# were still installing all 28 `[tools]` entries on every PR push, to run a
# commit-subject regex and one static analyzer. Nothing was red. Nothing could be.
#
# So this asks the question the other direction, over every workflow that spends
# a runner on a pull request:
#
#   1. Every `mise-action` step carries an `install_args` list. Counted
#      rather than parsed per step: one list per use is the invariant, and a
#      count is decidable without tracking YAML block structure — the same
#      constraint the `requested` scan above already works within.
#   2. Both auto-install variables are set. A list without them is DECORATIVE:
#      mise re-installs the missing tools at task time, which is the failure
#      CLOUD-180 measured in the `cross` job (rust in 13s, then the whole
#      toolchain rebuilt inside the work step) and which is indistinguishable
#      from a fix by reading the workflow.
#
# Scheduled and `workflow_run` workflows are out of scope deliberately: they are
# not on the PR path, they are not what the ledger is measuring, and widening
# this to them would be a different decision with a different cost argument.
#
# Pointer-only (non-negotiable 4): the workflow path and which half is missing.
# Never the tool set, never a log line.
# The two declarations sit HERE, at column 0, rather than beside the arms they
# corrupt. `mutant` reads them with `sed -n 's/^#MUTANT //p'`, so an indented
# one is invisible to it — and `shfmt` reindents any comment inside a block, so
# a column-0 comment beside those arms cannot survive the formatter either. The
# slugs name which arm each one reverts.
#MUTANT spawned-tool-need-not-be-installed|s@^		if ! grep -qxF "\$tool" <<<"\$installed"; then$@		if false; then@|no list installs is refused
#MUTANT pr-workflow-may-omit-install-args|s@^\t\tif \[\[ "\$lists" -ne "\$uses" \]\]; then$@\t\tif false; then@|with no install_args fails
#MUTANT pr-workflow-list-may-be-nonbinding|s@^\t\tif ! grep -qE "\$binding_task".*@\t\tif false; then@|without the auto-install variables fails
if [[ -d "$WORKFLOW_DIR" ]]; then
	pr_workflows=0
	for wf in "$WORKFLOW_DIR"/*.yml; do
		[[ -f "$wf" ]] || continue
		grep -qE '^[ \t]*pull_request:' "$wf" || continue
		uses=$(grep -cF 'uses: jdx/mise-action' "$wf")
		[[ "$uses" -gt 0 ]] || continue
		pr_workflows=$((pr_workflows + 1))

		lists=$(grep -cE '^[ \t]*install_args:' "$wf")
		if [[ "$lists" -ne "$uses" ]]; then
			echo "::error:: $wf runs mise-action $uses time(s) but declares $lists install_args list(s), so a pull_request job installs the whole toolchain. Narrow it to the tools that job invokes." >&2
			status=1
		fi

		# The ASSIGNMENT, set to false — not a mention. A substring search would
		# pass a workflow whose only occurrence is the comment explaining why the
		# variable matters, and it would pass one that sets it to "true", which is
		# the same hole wearing a fix's clothing.
		binding_task='^[ \t]*MISE_TASK_RUN_AUTO_INSTALL:[ \t]*"?false"?[ \t]*$'
		binding_exec='^[ \t]*MISE_EXEC_AUTO_INSTALL:[ \t]*"?false"?[ \t]*$'
		if ! grep -qE "$binding_task" "$wf" || ! grep -qE "$binding_exec" "$wf"; then
			echo "::error:: $wf narrows install_args but does not set MISE_TASK_RUN_AUTO_INSTALL and MISE_EXEC_AUTO_INSTALL, so mise re-installs the rest at task time and the list decides nothing (CLOUD-180)." >&2
			status=1
		fi

		# AND THE NAMES IN *THAT* WORKFLOW RESOLVE TOO. The pass above judges one
		# file, the one named by the first argument, and that was the whole gate
		# when `ci.yml` was the only workflow with per-job lists. It is not any
		# more: CLOUD-398 moved four jobs into `rust.yml`, taking their
		# `install_args` with them, and a rename in `mise.toml` that missed those
		# lists would have failed nowhere — `mise install` does not error on an
		# unknown tool name, so it surfaces later as "command not found" in
		# whichever step needed it. Same predicate, every file it applies to.
		if [[ "$wf" != "$WORKFLOW" ]]; then
			while IFS= read -r tool; do
				[[ -n "$tool" ]] || continue
				if ! grep -qxF "$tool" <<<"$declared"; then
					echo "::error:: $wf installs '$tool', which is not a [tools] entry in $CONFIG. CI would skip it and fail later as 'command not found'." >&2
					status=1
				fi
			done < <(
				awk '
					/^[ \t]*install_args:/ {
						sub(/^[ \t]*install_args:[ \t]*/, "")
						print
					}
				' "$wf" | tr -s '[:blank:]' '\n' | grep -v '^$' | sort -u
			)
		fi
	done
fi

# ---------------------------------------------------------------------------
# THE THIRD DIRECTION, AND IT IS THE ONE THAT COST TWO CI RUNS (CLOUD-480).
#
# Both directions above are about the install list and `[tools]`. Neither can see
# a tool a `batten.toml` row SPAWNS: `policy-modules-type-check` runs `opa check
# -s schema/ policy/` and `policy-lint-rule-tests` runs `regal test
# .regal/rules`, both were declared in `[tools]`, and neither was in `ci.yml`'s
# list. With `MISE_EXEC_AUTO_INSTALL: false` making that list binding, the two
# rows did not run slowly — they failed CLOSED, at `deny`, while passing locally
# where the tools are installed. `land` refuses that as a verify/CI disagreement
# and is right to, but nothing named the cause.
#
# SCOPED TO WHAT MISE OWNS, which is derived rather than allowlisted. A spawned
# binary can arrive three other ways: bundled with a bigger tool (`cargo` with
# `rust`), pre-installed on the runner (`gh`), or vendored as a submodule
# (`bats`). None of those belongs in an install list, and all three came back as
# findings on the first run of this block. Rather than carry a second list of
# exemptions — the drifting authority this task exists to refuse — the question
# narrows to tools mise DECLARES: if `[tools]` owns it, the install list must name
# it, and if it does not, mise was never going to install it anyway.
#
# Basename matching on both sides, deliberately: `[tools]` and the list hold
# backend-qualified keys (`aqua:open-policy-agent/opa`) and the spawn names a
# binary (`opa`), so the comparison is over the last path component. Approximate
# in the safe direction — it can fail to catch a mismatch, never invent one — and
# the precise mapping is mise's business rather than something to restate here.
owned=$(sed -E 's@.*[:/]@@' <<<"$declared" | sort -u)
spawned=$(
	grep -oE 'mise exec -- [a-z][a-z0-9._-]*' "$POLICY" 2>/dev/null |
		awk '{print $NF}' | sort -u |
		grep -xF -f <(printf '%s\n' "$owned") || true
)
if [[ -n "${spawned//[[:space:]]/}" ]]; then
	installed=$(
		awk '
			/^[ \t]*install_args:/ {
				sub(/^[ \t]*install_args:[ \t]*/, "")
				print
			}
		' "$WORKFLOW" | tr -s '[:blank:]' '\n' | grep -v '^$' |
			sed -E 's@.*[:/]@@' | sort -u
	)
	while IFS= read -r tool; do
		[[ -n "$tool" ]] || continue
		if ! grep -qxF "$tool" <<<"$installed"; then
			echo "::error:: $POLICY spawns '$tool' from a rule's check, but no install_args list in $WORKFLOW installs it. With auto-install off the row does not run slowly, it fails CLOSED — green locally, red in CI." >&2
			status=1
		fi
	done <<<"$spawned"
fi

if [[ "$status" -eq 0 ]]; then
	echo "ci-tools-check: all $count tools named in $WORKFLOW are declared in $CONFIG, every tool a $POLICY row spawns is installed there, and every pull_request workflow in $WORKFLOW_DIR carries a binding install_args list"
fi
exit "$status"
