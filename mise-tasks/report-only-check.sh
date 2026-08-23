#!/usr/bin/env bash
#MISE description="Gate: a report task stays off the landing path — absent from [tasks.verify] and from every pull_request workflow (pointer-only)"
#
# CLOUD-582. Two tasks here are REPORTS rather than gates — `coverage`
# (CLOUD-111) and `scorecard` — and both are non-gates by a decision that no
# exit code held. Each carries a long comment saying so, which is feedforward
# with no sensor: the whole of what kept them off the landing path was that
# nobody added them to it.
#
# The failure mode is quiet and one-directional. Adding a report to `verify` or
# to a `pull_request` workflow makes it a gate, and it then fails a branch for a
# NUMBER — a coverage percentage, or a scorecard check counting a deliberate
# design decision as a defect. That is the model-verdict shape non-negotiable
# rule 3 refuses, arriving as a one-line diff nobody reads as a policy change.
#
# WHY THIS IS NOT PART OF `ci-local-parity`, which parses the same two inputs.
# That gate asserts the FORWARD direction — every task CI runs is one `verify`
# runs — so CI is a confirmation rather than a discovery. This is the INVERSE:
# named tasks appear in neither. Composing them would give one task two
# properties that fail for opposite reasons, and the deny would have to explain
# which. They are cheap; two gates that each say one thing are the better trade.
#
# WHICH TASKS, and why the list is here rather than in `mise.toml`. A report is
# not a syntactic category — nothing in a task's declaration says "this emits a
# number nobody may block on" — so the set is a judgement, made once, written
# down where the gate that enforces it can be read beside it. A task added to
# this list is a decision to keep it off the landing path forever; removing one
# is a decision to allow it on, and both should be visible in the same diff as
# the gate.
#
# Pointer-only (non-negotiable 4): the task name and where it was found, never
# the matched line.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT report-on-the-landing-path-passes|s/^\texit 1$/\texit 0/|a report run by a pull_request workflow is refused

set -uo pipefail

manifest="${REPORT_ONLY_MANIFEST:-mise.toml}"
workflows="${REPORT_ONLY_WORKFLOWS:-.github/workflows}"
# Space-separated so a fixture can narrow it; the default is the real set.
read -r -a reports <<<"${REPORT_ONLY_TASKS:-coverage scorecard}"

violations=0
problem() {
	echo "::error:: report-only-check: $*" >&2
	violations=$((violations + 1))
}

if [[ ! -f "$manifest" ]]; then
	echo "::error:: report-only-check: no manifest at $manifest — nothing to judge" >&2
	exit 2
fi

# `[tasks.verify]`'s own block: its `depends` list plus its body, the same span
# `ci-local-parity` reads, so the two gates cannot disagree about what "verify
# runs this" means.
verify_block=$(awk '/^\[tasks\.verify\]/{p=1;next} /^\[/{p=0} p' "$manifest")
if [[ -z "$verify_block" ]]; then
	echo "::error:: report-only-check: no [tasks.verify] in $manifest, so there is nothing to judge a report against" >&2
	exit 2
fi

for task in "${reports[@]}"; do
	[[ -n "$task" ]] || continue

	# Word-bounded: `coverage` must not be satisfied by `COVERAGE_OUT_DIR`, and
	# must still fire on `"coverage"` inside a `depends` list.
	if grep -qE "(^|[^a-zA-Z0-9_:-])${task}([^a-zA-Z0-9_:-]|$)" <<<"$verify_block"; then
		problem "\`$task\` is a report, and [tasks.verify] names it — running it on the landing path makes a number a gate."
	fi
done

# A `pull_request` workflow is the other way onto the landing path, and the one
# `verify` cannot see. Scoped to that trigger deliberately: a scheduled workflow
# running a report is the whole point of the report existing.
shopt -s nullglob
for wf in "$workflows"/*.yml "$workflows"/*.yaml; do
	# Read once into a variable, then here-string: `grep -q` exits on its first
	# match, and under `pipefail` the SIGPIPE'd producer makes a pipeline report
	# failure on a MATCH — the inversion `pipefail-grep-check` exists to catch.
	triggers=$(awk '/^on:/{p=1;next} /^[a-z]/{p=0} p' "$wf")
	grep -q '^  pull_request:' <<<"$triggers" || continue

	body=$(cat "$wf")
	for task in "${reports[@]}"; do
		[[ -n "$task" ]] || continue
		if grep -qE "mise run ${task}([^a-zA-Z0-9_:-]|$)" <<<"$body"; then
			problem "\`$task\` is a report, and ${wf#"$workflows"/} runs it on pull_request — that spends a runner per push for a verdict nobody may block on."
		fi
	done
done

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: report-only-check: $violations violation(s). A report emits a number for a human; binding it to landing gates on a tool's opinion (non-negotiable rule 3). Keep it scheduled, or decide deliberately that it is a gate and remove it from this task's list." >&2
	exit 1
fi

echo "report-only-check: ${#reports[@]} report task(s) off the landing path — absent from [tasks.verify] and from every pull_request workflow"
