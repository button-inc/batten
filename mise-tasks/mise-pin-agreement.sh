#!/usr/bin/env bash
#MISE description="Gate: every tool version named in .mcp.json agrees with mise.toml's pin — the second place a pin is written cannot drift from the first"
#
# CLOUD-316. `.mcp.json` now NAMES the tool it launches — `mise exec
# "pipx:serena-agent@1.6.1" -- serena …` — because a bare `mise exec` provisions
# the whole toolchain before exec'ing anything, so one unrelated tool failing to
# install takes the server down with it. Scoping the exec is the fix.
#
# It buys that at the cost of writing a pinned version down twice. mise.toml
# owns the pin (it is what `mise install` and `mise.lock` read); `.mcp.json`'s
# copy is a REFERENCE to it. When the two disagree the failure is not a version
# mismatch, it is worse: `mise exec` treats the named version as a request and
# installs it, so a bump in mise.toml leaves the MCP server silently running the
# OLD version, with mise.lock, the SBOM and every other consumer describing the
# new one. Nothing surfaces that — the server starts fine.
#
# This is a property of the COMMITTED BYTES: two tracked files, no network, no
# session state. So unlike `mcp-attach-check` (its sibling from the same issue,
# which reads live logs and therefore runs on `UserPromptSubmit`), this belongs
# in the hk gate, where a bump that updates one file and not the other fails at
# check time. Same split the toolchain rule draws between `lock-complete` and
# `lock-currency.yml`: a property of the commit is a gate, a property of the
# world is a schedule.
#
# It is deliberately general over `.mcp.json` rather than special-cased to
# serena: any server whose args carry a `backend:tool@version` triple is
# checked, so a second MCP server added the same way inherits the gate without
# anyone remembering to widen it.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT unpinned-version-passes|s/^exit "\$fail"$/exit 0/|does not pin fails, naming both

set -euo pipefail

mcp="${1:-.mcp.json}"
toml="${2:-mise.toml}"

if [[ ! -f "$mcp" ]]; then
	echo "mise-pin-agreement: no $mcp — nothing to check"
	exit 0
fi
if [[ ! -f "$toml" ]]; then
	echo "::error:: $toml is missing; cannot resolve the authoritative pins" >&2
	exit 2
fi
# An unparseable .mcp.json must never be reported as a clean pass; an EMPTY
# result must never short-circuit the shape check below, which is the predicate
# that catches a revert to a bare exec (that revert removes every pin, so an
# early `exit 0` here would greenlight exactly the defect this gate is for).
if ! jq -e . "$mcp" >/dev/null 2>&1; then
	echo "::error:: $mcp is not readable JSON" >&2
	exit 2
fi
pinned=$(jq -r '[.mcpServers // {} | to_entries[] | .key as $s | (.value.args // [])[]
	| select(type == "string") | select(test("^[a-z0-9]+:.+@.+$")) | "\($s)\t\(.)"] | .[]' "$mcp" 2>/dev/null)

fail=0
report() {
	[[ "$fail" = 0 ]] && echo "::error:: $mcp disagrees with $toml, or launches a server unscoped:" >&2
	printf '  %s\n' "$1" >&2
	fail=1
}

checked=0
while IFS=$'\t' read -r server ref; do
	[[ -n "$ref" ]] || continue
	tool="${ref%@*}"
	want="${ref##*@}"
	checked=$((checked + 1))

	# The pin as mise.toml writes it: a quoted key, since every backend-prefixed
	# tool name contains a colon. Value may be quoted or a table; only the plain
	# string form is a pin this gate can compare, and that is the form used.
	have=$(sed -n -E "s/^[[:space:]]*\"${tool//\//\\/}\"[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "$toml" | head -n 1)

	if [[ -z "$have" ]]; then
		report "$server: $tool@$want — $toml carries no pin for $tool at all"
	elif [[ "$have" != "$want" ]]; then
		report "$server: $tool@$want — $toml pins $have"
	fi
done <<<"$pinned"

# --- the shape that made the pin necessary ------------------------------------
#
# The pin exists because the exec is SCOPED. Reverting to a bare `mise exec --`
# would remove every reference above and leave this gate reporting "nothing to
# check" — green, with the defect restored. So the shape is gated directly: a
# server launched through `mise exec` must name at least one tool before `--`.
#
# This is the regression the issue is actually about. Checking only the versions
# would gate the cost of the fix and not the fix.
# Selected by ARGV, not by `command`. The command is no longer always `mise`:
# CLOUD-714 interposes `mise-tasks/<server>-mcp`, a shim that records the spawn
# and `exec`s `mise "$@"` with these same args. Keying on `command == "mise"`
# would have made that shim silently exempt the scoped-exec check below — the
# gate reporting a clean pass while the property it exists for went unchecked,
# which is the same fail-open this file's header warns about one paragraph up.
# `args[0] == "exec"` is what actually identifies a mise exec launch, shim or no.
while IFS= read -r server; do
	[[ -n "$server" ]] || continue
	args=$(jq -r --arg s "$server" '[.mcpServers[$s].args // [] | .[] | select(type == "string")] | .[]' "$mcp" 2>/dev/null)
	# Everything up to the first `--` is mise's own argv: the subcommand plus
	# the tools it is scoped to. A bare exec has nothing between them.
	scoped=$(awk 'BEGIN{seen=0} /^--$/{exit} {if (seen) print} /^exec$/{seen=1}' <<<"$args")
	if [[ -z "$scoped" ]]; then
		report "$server: \`mise exec\` names no tool — a bare exec provisions the whole toolchain and dies with any one of it (CLOUD-316)"
	fi
done < <(jq -r '[.mcpServers // {} | to_entries[] | select(((.value.args // [])[0] // "") == "exec") | .key] | .[]' "$mcp" 2>/dev/null)

[[ "$fail" = 0 ]] && echo "mise-pin-agreement: $checked tool reference(s) in $mcp agree with $toml, and every \`mise exec\` launch is scoped"
exit "$fail"
