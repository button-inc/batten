#!/usr/bin/env bash
#MISE description="Gate: this container can actually do the work — egress reaches api.github.com and the credential carries the claims the lifecycle needs. Halts for manual repair; never repairs."
#
# CLOUD-261. `doctor` asserts the provisioning mise does not own. This asserts
# the things NOTHING in the repo owns: the container's egress policy and the
# credential it was handed. Both are supplied from outside, both are invisible
# until a task deep in the lifecycle fails in someone else's name, and neither
# is repairable from inside the session.
#
# Measured, on the container this was written for:
#
#   * ambient NO_PROXY omitted api.github.com, so mise's own release resolver
#     403'd and `mise install` died naming `ubi:rust-cross/cargo-zigbuild` — a
#     proxy policy wearing a third-party-tool costume.
#   * the credential read the repo fine but carried no `checks=read`, so
#     `ci-wait` could not see CI. A session verified green, readied a PR, and
#     then could not land it — and read the toolchain as broken rather than the
#     token as under-scoped.
#
# WHY THIS HALTS INSTEAD OF REPAIRING, which is the opposite of `doctor`.
# doctor's failures have one correct outcome an agent can reach: check out a
# submodule, install a target. These need a human to change a token's scopes or
# a container's egress policy. An agent that improvises past them does not
# recover — it produces work it cannot land, and concludes the repo is at fault.
# So the verdict is a stop sign, not a to-do list.
#
# WHAT THIS IS NOT SAYING. A correct container passes this silently, and main's
# landed history is the evidence that passing is the norm — this is a detector
# for a DEVIATION, not a description of the environment. Nothing it reports is a
# reason to rewrite a task, a memory, or AGENTS.md to accommodate a broken
# container. If it fires, the container is what gets fixed.
#
# Every probe is READ-ONLY, and the toolchain-dependent ones are skipped under
# `--degraded` (the hook passes it when provisioning already failed), so a
# missing binary is never reported as a missing permission.
set -uo pipefail

# `set -e` is deliberately absent — this collects every root cause rather than
# aborting on the first — so the cd guards itself. A preflight that silently ran
# from the wrong directory would probe the wrong repo.
cd "$(git rev-parse --show-toplevel)" || exit 1

degraded=no
[ "${1:-}" = "--degraded" ] && degraded=yes

# Root causes are collected rather than raised one at a time: a broken container
# is usually broken in more than one way, and a human repairing it wants the
# whole list, not the first item followed by another session to find the second.
broken=()
detail=""

# --- egress: can mise resolve a release at all? -------------------------------
#
# Pure, instant, and deliberately first: it is the cause the failed install
# downstream is a symptom of, so naming it here is what stops the next reader
# debugging cargo-zigbuild. The decision itself lives in `egress-check` so it is
# testable without a proxy — same split as doctor / doctor-check.
egress=$("$(dirname "$0")/egress-check.sh" "${HTTPS_PROXY:-${https_proxy:-}}" "${NO_PROXY:-${no_proxy:-}}")
if [ "$egress" = unfenced ]; then
	broken+=("EGRESS — api.github.com is proxied and not fenced out of NO_PROXY.
     mise resolves every tool's release through that host, so \`mise install\`
     fails on the first third-party tool and blames the tool.
     REPAIR (outside the session): add api.github.com, objects.githubusercontent.com,
     codeload.github.com and uploads.github.com to the container's AMBIENT NO_PROXY.
     mise.toml's [env] already appends them, and CANNOT help here: mise applies
     [env] to the processes it runs, after its own resolver has made the call.")
fi

# --- credential: can it drive the lifecycle? ----------------------------------
#
# gh-preflight already walks the read endpoints the tasks call and reports the
# claim GitHub itself names in each 403 (X-Accepted-GitHub-Permissions). It is
# the diagnosis and it already exits non-zero; what was missing was anything
# running it before a session spent an hour rediscovering the same fact one task
# at a time. Adopted rather than rebuilt (AGENTS.md: adopt prior art).
if [ "$degraded" = yes ]; then
	echo "container-preflight: toolchain incomplete — skipping the GitHub probes (a missing gh is not a missing permission)"
else
	preflight=$(mise run gh-preflight 2>&1)
	rc=$?
	detail="$preflight"
	case "$rc" in
	0) ;;
	1)
		broken+=("CREDENTIAL — the token reads the repo but is missing read claim(s)
     the lifecycle needs. Work can be verified and pushed, and then never landed:
     ci-wait cannot see CI state and land cannot see the merge.
     REPAIR (outside the session): grant the claims gh-preflight names below, or
     supply a classic PAT scoped \`repo\`, which bundles checks=read.")
		;;
	*)
		# Deliberately a fork, not an assertion: an Actions/API incident looks
		# exactly like an absent token from here, and sending someone to rotate a
		# working credential during an outage is its own expensive mistake.
		broken+=("GITHUB UNREACHABLE — could not probe the API at all. Either the token
     is absent/unauthenticated, or GitHub is having an incident.
     CHECK FIRST: https://www.githubstatus.com/api/v2/summary.json — during an
     incident this clears on its own and no credential should be touched.")
		;;
	esac
fi

if [ "${#broken[@]}" -eq 0 ]; then
	echo "container-preflight: egress fenced, credential carries every probed read claim"
	exit 0
fi

{
	echo
	echo "::error:: container-preflight: THIS CONTAINER CANNOT DO THE WORK."
	echo
	for cause in "${broken[@]}"; do
		echo "  * $cause"
		echo
	done
	if [ -n "$detail" ]; then
		echo "  gh-preflight said:"
		printf '%s\n' "$detail" | sed 's/^/    /'
		echo
	fi
	echo "  HALT. None of the above is a defect in this repository and none is"
	echo "  repairable from inside the session — that is why this stops rather than"
	echo "  working around them. Do not rewrite tasks, memories or AGENTS.md to"
	echo "  accommodate what you find here, and do not improvise a workaround and"
	echo "  carry on: the work will verify, push, and then fail to land."
	echo "  Report these root causes, repair the container, start a new session."
} >&2
exit 1
