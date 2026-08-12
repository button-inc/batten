#!/usr/bin/env bash
#
# The `PreToolUse` entry point: hand the payload to the engine (CLOUD-312).
#
# A launcher rather than a bare `batten hook` in `.claude/settings.json`,
# because that file can express neither a `cd` nor a fallback chain, and both
# are load-bearing:
#
#   * `load_policy` reads `./batten.toml` with NO upward walk (lib.rs:869-875).
#     A hook fired while the session's cwd is `crates/batten` would resolve
#     `Policy::declaring_nothing()` and allow everything, silently — a guard
#     that is installed, runs, and decides nothing. The `cd` is the whole
#     defence, so it comes first and its failure is an allow.
#
#   * There is no `batten` on PATH here and nothing puts `target/release` on it.
#     Every gate in `mise.toml` invokes `cargo run --quiet -p batten --` so it
#     judges the working tree's engine and config together, which is right for a
#     gate and disqualifying here: this runs on EVERY mediated tool call, and a
#     cargo round trip per call also contends for the target-dir lock `hk.pkl`
#     deliberately serialises.
#
# Fails OPEN on everything — no binary, no repo, an unreadable payload — because
# no failure Batten can produce may be the reason a session cannot proceed
# (CLOUD-312 §5). What it must not do is fail open QUIETLY: the shell guards it
# replaces could not be absent, so an operator who has never built the binary
# would otherwise get a session with no mediation and no symptom. Hence the
# stderr line, and the once-per-session UI message below.
set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}" 2>/dev/null || exit 0

# First executable wins. BATTEN_BIN is the documented override and exists for
# the same reason `mise-tasks/linear-check:74` has one: a suite needs to point
# the launcher at a stub without rebuilding.
bin=""
for candidate in \
	"${BATTEN_BIN:-}" \
	"target/release/batten" \
	"target/debug/batten" \
	"$(command -v batten 2>/dev/null || true)"; do
	if [ -n "$candidate" ] && [ -x "$candidate" ]; then
		bin="$candidate"
		break
	fi
done

if [ -z "$bin" ]; then
	echo "::error:: batten-hook: no batten binary (looked at \$BATTEN_BIN, target/release/batten, target/debug/batten, PATH) — mediation is OFF for this session. Run: mise run build:release" >&2
	# Say it once per session, in the channel a human actually reads. Bounded by
	# a marker file the way `stop-guard` bounds itself with `stop_hook_active`:
	# an unbounded warning on every tool call is noise, and noise is how a real
	# signal stops being read. A session with no id degrades to per-invocation
	# handling rather than to silence.
	marker="${TMPDIR:-/tmp}/batten-hook-nobin.${CLAUDE_SESSION_ID:-$$}"
	if [ ! -e "$marker" ] && : >"$marker" 2>/dev/null; then
		# No backticks in this literal: shellcheck reads them as a command
		# substitution it cannot see into (SC2016), and a suppression here would
		# be a directive nobody re-reads. Plain text costs nothing — this is a
		# UI message, not markdown.
		printf '%s\n' '{"systemMessage":"Batten is not mediating tool calls: no batten binary was found. Policy in batten.toml is NOT being enforced. Run: mise run build:release"}'
	fi
	exit 0
fi

exec "$bin" hook --harness claude-code
