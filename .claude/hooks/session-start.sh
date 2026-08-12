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
#
# It also PREFLIGHTS THE CONTAINER (CLOUD-261), by calling `container-preflight`
# after provisioning. "The toolchain installed" and "this container can do the
# work" are different questions, and the second one used to be answered three
# tasks in, by a failure wearing someone else's name. That task owns the what
# and the why; this hook owns only the WHEN — the very beginning of the session,
# before any work is planned against a container that cannot land it.
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
# MISE_LOCKFILE=false makes it a PURE install (CLOUD-223). A cold install of
# `ubi:rust-cross/cargo-zigbuild` otherwise appends
# `platforms.linux-x64-cargo-zigbuild` — platform plus the exe name, checksum,
# no url — to the tracked lockfile. `mise lock` cannot produce that key
# (measured: it locks 0 platform entries for the ubi backend, all 7 skipped), so
# it is install residue rather than a lock, and `mise run lock-complete` rejects
# it by name. Every session therefore opened with a dirty tree and a red gate no
# branch had caused, and it got committed twice: 17b8436, reverted by 3bee7d2,
# then a7cef00 on a branch named for unrelated work. Warm installs never rewrite
# it, so the cost looked intermittent.
#
# The authority is now `[settings] lockfile = false` in mise.toml, which denies
# the write to EVERY caller — including the sandbox's own provisioning, which
# runs before this hook and so kept dirtying the tree after the per-caller fix
# landed. This line is the belt to that suspenders: it keeps the install pure
# even where the setting is overridden by an ambient MISE_LOCKFILE. Asserted by
# tests/session-start.bats.
#
# Provisioning has no business writing the lockfile at all: currency is owned by
# .github/workflows/lock-currency.yml, on a schedule, off the landing path.
step mise-install env MISE_LOCKFILE=false mise install
# bats lives in tests/bats; `mise run test:bats` cannot run without it.
step submodules git submodule update --init --recursive

# `doctor` joins the same synchronous window (CLOUD-218). `mise install` returning
# is not "the toolchain is settled": doctor provisions what mise does NOT own —
# the rustup cross targets above all — and left outside this window it runs for
# the first time inside the first `mise run verify`, concurrently with whatever
# else the sandbox is still laying down. Measured on a cold container
# 2026-08-07: that first verify died in doctor with
#
#   error: failed to install component: 'rust-std-aarch64-apple-darwin',
#   detected conflict: '.../libaddr2line-….rlib'
#   ::error:: could not install rust target aarch64-apple-darwin; …
#
# and a second doctor, nothing changed but time, exited 0. The message names
# cross-compilation, so it costs the reader a debugging session on a machine
# where nothing is broken — CLOUD-196's failure mode in different clothes.
#
# This is not a retry: it does not make the race survivable, it empties the
# window the race needs. CLOUD-220's per-toolchain mutex in `target-ensure`
# serializes concurrent WRITERS; this leaves the later ones nothing to write,
# because by the time any task runs the targets are already installed. Both
# stand — the mutex covers the warm case (the verify graph racing itself,
# CLOUD-201), this covers the cold one.
#
# `doctor` itself is unchanged, and runs AFTER the two steps above: its rustup
# half needs the mise-provisioned toolchain, and its submodule half is a repair
# for the case the step above did not reach. It goes through `step`, so the
# loud-failure contract is the same as every other one — a `::error::` line, the
# log pointer, and a non-zero exit at the end.
step doctor mise run doctor

# The binary the `PreToolUse` hook executes (CLOUD-312). Built HERE, in the
# synchronous provisioning window, for the same reason the steps above are: a
# fresh container has no `target/`, and `.claude/hooks/batten-hook.sh` fails
# OPEN when it finds none — so without this a session would start with policy
# unenforced, which is a state the guards it replaced could not reach. The
# launcher still says so loudly if this step did not run or did not succeed;
# belt and braces, because a silent unmediated session is the failure with no
# symptom.
step batten-build mise run build:release

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
fi

# --- can this container do the work at all? -----------------------------------
#
# Provisioning succeeding is a different question from the container being
# usable, and the difference is invisible until a task deep in the lifecycle
# fails in someone else's name. `container-preflight` asks the second question
# and halts on it; see that task for what it checks and why each is unrepairable
# from inside the session.
#
# It runs even when provisioning failed, because a failed install is usually a
# SYMPTOM of what it diagnoses (a proxied api.github.com), and reporting the
# cause beside the symptom is the whole point. Its own `--degraded` argument
# tells it not to trust toolchain-dependent probes in that state.
if [ "$fail" -ne 0 ]; then
	mise run container-preflight -- --degraded || fail=1
else
	mise run container-preflight || fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "session-start: toolchain provisioned (mise install, submodules, doctor); container preflight clean"
