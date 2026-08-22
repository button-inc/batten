#!/usr/bin/env bash
#MISE description="A required check went red: cancel the runs still spending on this SHA for a verdict nobody will read"
#
# Usage: mise run abandon-matrix <sha> [reason]
#
# CLOUD-900. A PR here buys eighteen required checks across five `pull_request`
# workflows, and every one of those files supersedes ONLY ITS OWN runs — each
# carries its own `concurrency` group, and there is no cross-workflow signal at
# all. So the first red check stops nothing, and up to seventeen siblings run to
# completion for a verdict nobody will read.
#
# The two most expensive are exactly the ones no cheap early check can reach:
# `windows` is 50.6% of the CI bill at ~11 minutes (CLOUD-813) and lives in
# `rust.yml`, while the bats suite is the pole of `ci` (CLOUD-386) in `ci.yml`.
# The worst shape is the cheapest failure — `commit-lint` renders a verdict in
# ~90 seconds and the rest of the matrix then bills out in full behind it.
#
# THIS TASK DOES NOT DECIDE THAT THE BRANCH IS RED, and that is the whole reason
# it is this small. `checks-green` is the one definition of "is this SHA green"
# (CLOUD-327, CLOUD-346, CLOUD-391), `ci-wait` polls around it, and `land` calls
# this only from the arm it has already reached by that verdict — past the lease
# test and past the provisioning-transient test, where the red is known to be an
# answer about the tree. Re-deriving membership from `$CI_REQUIRED_CHECKS` here
# would be a SECOND AUTHORITY for one fact, which is the CLOUD-351 shape and the
# mistake this repository keeps paying for.
#
# WHY NOT A STEP IN THE FAILING JOB, which is the obvious placement and was the
# first design. Three costs, none of them worth the seconds it would save:
# every required job in five workflows would carry the step and its matrix-name
# plumbing; `ci-local-parity` property 3 would refuse a workflow running a task
# `verify` does not, so the rule would ship with an exemption carved for it; and
# a job that dies IN PROVISIONING would abandon its siblings, which is precisely
# the case `absorbed_transient` re-runs — `gh run rerun --failed` restores the
# failed jobs of a run, and nothing restores a sibling run that was cancelled.
# Calling from `land` gets the same saving from one call site that already holds
# the credential, the SHA and the verdict.
#
# THE RUN CARRYING THE FAN-IN IS NEVER CANCELLED. `final` is the single context
# `protect-main` requires (`batten.toml`'s `[ci].required_checks`), it is
# `always()` over a `needs:` assertion (CLOUD-351), and `land` cannot land
# without it. Cancelling its run leaves that context `cancelled`, which is not an
# answer (CLOUD-363) — so the saving would buy a branch that can never grade and
# never land. `$CI_FANIN_WORKFLOW` names the file it lives in, declared once in
# mise.toml [env] beside the roster and checked against the tree by
# `ci-local-parity` property 17 rather than trusted.
#
# The cost of that exclusion, stated rather than buried: a red `windows` does not
# stop `ci`, because `ci` shares a run with the fan-in. The saving is asymmetric
# by construction — anything red kills `windows`, and only the fan-in's own file
# is ever spared — and that is the trade the wedge is worth.
#
# THIS IS NOT "CANCELLING SOMEONE ELSE'S RUNS". `cancel_own_run` in this same
# file already cancels every run on a head SHA, and its header makes the argument
# this borrows: a head SHA is one no other branch has, so the blast radius is one
# push's worth of runs BY CONSTRUCTION rather than by filtering. CLOUD-240's
# "supersede your own runs, never someone else's" is about another REF's runs,
# and no other ref is reachable from here.
#
# BEST-EFFORT THROUGHOUT, AND NEVER A VERDICT. A cancellation that is refused
# costs the minutes it would have saved and changes no conclusion, so nothing
# here is guarded into a stop and every path exits 0. The caller is on its way to
# a `die` that names the real failure; a cleanup step that could not reach the
# API must not replace that diagnosable message with a confusing one.
#
# Output is pointer-only per non-negotiable rule 4: a run id and a workflow path,
# never a log line from the run being stopped.
set -uo pipefail

say() { echo "abandon-matrix: $*"; }

# Exit 0 on every early return. See the best-effort note in the header.
give_up() {
	say "$* — nothing cancelled"
	exit 0
}

sha="${1:-${ABANDON_SHA:-${SHA:-}}}"
[[ -n "$sha" ]] || sha=$(git rev-parse HEAD 2>/dev/null || true)
[[ -n "$sha" ]] || give_up "no SHA to abandon: no argument, no \$ABANDON_SHA, no git HEAD"

# Free text, for the pointer only. It is never parsed and never decides anything
# — the decision was `checks-green`'s, upstream of this call.
reason="${2:-a required check went red}"

fanin_workflow="${CI_FANIN_WORKFLOW:-}"
[[ -n "$fanin_workflow" ]] ||
	give_up "CI_FANIN_WORKFLOW is unset — run this through \`mise run abandon-matrix\`, which is where the fan-in is declared. Without it this cannot tell which run carries the fan-in, and cancelling that one wedges the branch"

repo="${REPO:-${GH_REPO:-}}"
[[ -n "$repo" ]] || repo='{owner}/{repo}'

# `status != "completed"` is the whole filter: a run that has already finished
# bills nothing further, so asking to cancel it is an API call that buys nothing.
# `per_page=100` because a head SHA carries a handful of runs, not a page
# boundary's worth.
runs=$(gh api "repos/$repo/actions/runs?head_sha=$sha&per_page=100" \
	--jq '.workflow_runs[]? | select(.status != "completed") | "\(.id)\t\(.path)"' 2>/dev/null) ||
	give_up "could not list the runs on ${sha:0:8}"

[[ -n "${runs//[[:space:]]/}" ]] || give_up "nothing still in flight on ${sha:0:8}"

cancelled=0
spared=0
while IFS=$'\t' read -r id path; do
	[[ -n "$id" ]] || continue

	if [[ "$path" = "$fanin_workflow" ]]; then
		spared=$((spared + 1))
		say "sparing run $id — $path carries the fan-in, and an ungraded fan-in wedges the landing"
		continue
	fi

	if gh api -X POST "repos/$repo/actions/runs/$id/cancel" >/dev/null 2>&1; then
		cancelled=$((cancelled + 1))
		say "cancelled run $id ($path) on ${sha:0:8} — $reason"
	else
		# Not a stop, and not silent either: a refused cancellation is exactly
		# the minutes this task exists to save, so it is worth a pointer even
		# though it changes no verdict.
		say "cancellation refused for run $id ($path) on ${sha:0:8} — it bills out"
	fi
done <<<"$runs"

say "$cancelled run(s) cancelled, $spared spared on ${sha:0:8}"
