#!/usr/bin/env bash
#MISE description="Evaluate the .pkl files given as arguments, so a malformed hk.pkl fails at check time rather than when a hook tries to run"
#
# Plain `pkl eval`, plus one guardrail: pkl resolves `amends "package://..."` over
# the network on a cold cache and trusts only its own bundled roots, so a sandbox
# that intercepts TLS makes that fetch fail as if the config were malformed. Where
# such a bundle is present, hand it over. See `mem:github-access`.
#
# **It reports pkl's exit status, and that had to be made true.** Every path
# below used to end in `exit 0` or in an `echo` whose status became the task's,
# with no `set -e` to stop the failing evaluation reaching them — so the step
# passed on a malformed `hk.pkl` and on an unreachable package alike. A gate that
# cannot fail is worse than no gate, because the gate's presence is what stops
# anyone looking (CLOUD-418). Found by writing `tests/pkl-check.bats`, which is
# the first suite this task has had.
set -uo pipefail

# One place that runs pkl and one place that decides, so a second invocation
# cannot grow a third exit path. The success line is printed only past the
# verdict; a failing run says nothing here, because pkl has already said it on
# stderr and repeating it would be a second authority on the same failure.
run_pkl() {
	local ca
	for ca in "${SSL_CERT_FILE:-}" /root/.ccr/ca-bundle.crt; do
		if [[ -n "$ca" ]] && [[ -f "$ca" ]]; then
			pkl eval --ca-certificates "$ca" "$@" >/dev/null
			return
		fi
	done
	pkl eval "$@" >/dev/null
}

run_pkl "$@" || exit 1
echo "pkl-check: $# file(s) evaluate cleanly"
