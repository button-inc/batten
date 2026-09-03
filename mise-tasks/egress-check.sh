#!/usr/bin/env bash
#MISE description="The pure decision behind the session preflight: can mise's own release resolver reach api.github.com, given the ambient proxy environment?"
#
# mise resolves every tool's release through GitHub's API host, api.github.com.
# Where an egress proxy fronts the network and injects a repo-scoped token, that
# host answers 403 for THIRD-PARTY tool repos (`GitHub access to this repository
# is not enabled for this session`), and `mise install` fails on the first such
# tool. mise.toml's [env] block already appends api.github.com to NO_PROXY for
# exactly this reason.
#
# THE PART THAT MAKES THIS A SEPARATE CHECK: that guard cannot fix itself. mise
# applies its own [env] to the processes it RUNS, after its release resolver has
# already made the HTTP call that picks the tool version. So a container whose
# AMBIENT NO_PROXY omits api.github.com fails during `mise install` — before any
# mise.toml setting is in play — and the failure names the tool repo rather than
# the proxy, which is what makes it expensive to read.
#
# THIS IS NOT THE NORM, AND MUST NOT BE READ AS ONE. A correctly provisioned
# container either has no proxy at all or already carries the fence in its
# ambient environment; main's landed history is the evidence that this is the
# usual case. This check exists to catch the DEVIATION at the start of a session
# rather than three tasks in, and its verdict is a statement about one container,
# never about the repo or the toolchain.
#
# Split from the hook that calls it for the reason doctor-check is split from
# doctor: the decision is the part worth testing, and it only tests if it is
# callable without the thing it decides about. Both values are ARGUMENTS, never
# reads of the live environment, so the suite can drive every combination.
#
# Verdicts, one word on stdout:
#
#   ok         no proxy is set (nothing to fence), or the proxy is set and
#              api.github.com is fenced out of it. mise can resolve releases.
#   unfenced   a proxy is set and api.github.com is NOT fenced. `mise install`
#              will fail on the first third-party tool, and no mise.toml setting
#              can prevent it.
#
# Exit is 0 for a delivered verdict and 2 for a malformed call: this classifies,
# it does not adjudicate. The caller decides what a verdict is worth.
#
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
# The mutation loosens the whole-entry wildcard test into a match-anything glob,
# which is the substring trap in its most generous form: EVERY entry then reads
# as a total bypass, so the broken container and the bypassed one become one
# answer. It discriminates because two cases disagree under it — the wildcard
# host and the GitHub-hosts-only container both flip to `ok`.
#MUTANT wildcard-matched-loosely|s@== '\*'@== \*@|a wildcard host is NOT a total bypass
set -uo pipefail

usage() {
	echo "usage: egress-check <https-proxy-value> <no-proxy-value>" >&2
	exit 2
}

# Both arguments are required but either may legitimately be EMPTY — "no proxy
# set" and "no NO_PROXY set" are the two most interesting inputs. So arity is
# checked, never emptiness.
[[ "$#" -eq 2 ]] || usage

proxy="$1"
no_proxy="$2"

# No proxy fronting the network: nothing is carried by one, so there is nothing
# to fence. This is the ordinary developer machine and most CI runners.
if [[ -z "$proxy" ]]; then
	echo "ok"
	exit 0
fi

# A TOTAL BYPASS IS THE ONLY OTHER `ok`, and narrowing `ok` to it is this
# program's whole correction (CLOUD-1399).
#
# `*` is matched as a WHOLE ENTRY, never as a substring, and that is the one
# place this file cannot be generous: `*.api.github.com` contains a `*` and
# bypasses exactly one host, so a substring read would call the broken container
# a bypassed one — the false `ok` the header says costs most. Entries are split
# on commas and trimmed, the way every client that honours a wildcard reads them.
IFS=',' read -r -a entries <<<"$no_proxy"
for entry in "${entries[@]}"; do
	entry="${entry#"${entry%%[![:space:]]*}"}"
	entry="${entry%"${entry##*[![:space:]]}"}"
	if [[ "$entry" == '*' ]]; then
		echo "ok"
		exit 0
	fi
done

# The host mise's resolver calls. Matched as a substring rather than by splitting
# on commas, because NO_PROXY has no single normative syntax — entries appear
# bare, dot-prefixed, and wildcard-prefixed across tools — and any of those forms
# containing this host means some implementation will honour it. A false "ok"
# here would be worse than a false "unfenced": the first hides the diagnosis the
# session needs, the second only asks a human to look.
#
# `unfenced` KEEPS ITS EXACT OLD MEANING — api.github.com is proxied, so `mise
# install` dies on the first third-party tool — because `container-preflight`
# reads that token to print that diagnosis, and re-pointing it at a broader
# question would trade a precise remedy for a vaguer one.
#
# `partial` IS THE STATE THAT USED TO READ `ok`. A container fencing the GitHub
# hosts and nothing else lets mise resolve releases, so the old question was
# answered — and still routes everything else through a proxy that injects a
# repo-scoped token, which the decision refuses. Splitting it out is a strict
# NARROWING: nothing this program once refused is now accepted, and the one input
# whose verdict moved is the one that was being read as compliance.
case "$no_proxy" in
*api.github.com*) echo "partial" ;;
*) echo "unfenced" ;;
esac
exit 0
