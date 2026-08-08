#!/usr/bin/env bash
# SessionStart: perform the per-clone setup AGENTS.md documents, before the
# session (and its project-scoped MCP servers) start.
#
# Why this exists (CLOUD-196). `.mcp.json` launches Serena with
# `mise exec -- serena start-mcp-server`, and `mise exec` INSTALLS a missing
# tool on demand. On a cold container that install runs inside the MCP client's
# startup window: measured 24s for `pipx:serena-agent`, the handshake did not
# complete, and MCP servers are not retried mid-session — so Serena was absent
# for a whole session while being perfectly runnable seconds later. Nothing was
# wrong with Serena or with mise; the per-clone `mise install` step simply never
# ran, so `exec` was doing an installer's job at the worst possible moment.
#
# This hook is deliberately SYNCHRONOUS (no `{"async": true}` line). Async would
# reintroduce exactly the race it exists to close: the session would start while
# the install was still running. The cost is paid only when cold — a warm
# `mise install` measured 0.067s.
#
# Failure is loud, never silent: a session that could not provision its
# toolchain must say so, because the original defect's whole signature was an
# absence with no error anywhere.
#
# This hook is NECESSARY BUT NOT SUFFICIENT. Measured on a genuinely cold
# container: the hook ran and completed before the session started, serena was
# installed and startable (21 tools, 1.1s warm) — and it was STILL absent from
# the session. A `.mcp.json` server is project-scoped and requires per-project
# approval; a cold container gets a fresh `~/.claude.json` whose
# `enabledMcpjsonServers` is `[]`, and a remote session has nobody to answer the
# approval prompt. That second gate is closed by committing
# `"enabledMcpjsonServers": ["serena"]` in .claude/settings.json — do not remove
# it thinking this hook covers the case. Both are load-bearing.
set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}" || exit 0

fail=0
step() { # step <label> <cmd...>
	local label="$1"
	shift
	if ! "$@" >/tmp/session-start-"$label".log 2>&1; then
		echo "::error:: session-start: $label failed — see /tmp/session-start-$label.log" >&2
		tail -5 /tmp/session-start-"$label".log >&2
		fail=1
	fi
}

# The three per-clone steps from AGENTS.md ("Per clone: mise install, git
# submodule update --init, hk install"), each idempotent.
#
# mise install is the load-bearing one: it is what makes `mise exec` in
# .mcp.json a pure exec rather than an implicit install.
#
# MISE_LOCKFILE=false makes it a PURE install (CLOUD-223). `[settings] lockfile
# = true` in mise.toml means a cold install of `ubi:rust-cross/cargo-zigbuild`
# appends `platforms.linux-x64-cargo-zigbuild` — platform plus the exe name,
# checksum, no url — to the tracked lockfile. `mise lock` cannot produce that
# key (measured: it locks 0 platform entries for the ubi backend, all 7
# skipped), so it is install residue rather than a lock, and `mise run
# lock-complete` rejects it by name. Every session therefore opened with a dirty
# tree and a red gate no branch had caused, and it got committed twice: 17b8436,
# reverted by 3bee7d2, then a7cef00 on a branch named for unrelated work. Warm
# installs never rewrite it, so the cost looked intermittent.
#
# Provisioning has no business writing the lockfile at all: currency is owned by
# .github/workflows/lock-currency.yml, on a schedule, off the landing path.
# Measured: with this set, a cold install of that tool leaves `git status
# --porcelain` empty. Asserted by tests/session-start.bats — dropping it puts
# the dirtying back.
step mise-install env MISE_LOCKFILE=false mise install
# bats lives in tests/bats; `mise run test:bats` cannot run without it.
step submodules git submodule update --init --recursive

# `hk install` is deliberately NOT run here, though AGENTS.md lists it as a
# per-clone step. The hook it generates is `exec hk run pre-commit`, calling
# `hk` bare — which resolves only where mise's shims are on PATH. In this
# environment they are not, so installing it makes every `git commit` fail with
# `hk: not found`. Measured: adding the step here broke the very commit that
# added it. The gate is still enforced, by `mise run ci`/`verify` and by CI;
# a local pre-commit hook is a convenience, and a broken one is worse than
# none. Restoring it needs the PATH question answered first (CLOUD-196).

if [ "$fail" -ne 0 ]; then
	echo "::error:: session-start: setup incomplete — expect missing tools or MCP servers" >&2
	exit 1
fi
echo "session-start: toolchain provisioned (mise install, submodules)"
