#!/usr/bin/env bash
# SessionStart: perform the per-clone setup AGENTS.md documents, at the start of
# the session.
#
# NOT before the MCP servers start, which this header claimed for its whole life
# and CLOUD-734 measured false. Two samples, one per container incarnation on
# 2026-08-19/20: the generated MCP config is written, the client opens its
# connection logs ~2.4s later, and this hook writes its first byte ~5s after
# that — the connections are initiated BEFORE the hook and complete while it is
# still provisioning. What rescues the install fix below is therefore not
# ordering but the client's 120s connect timeout: serena's connection was
# established 45.5s in, from inside this hook's window. CLOUD-316 recorded that
# timeout as 30s, at which this session would have lost serena outright.
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

# THE SESSION STAMP (CLOUD-431), written before anything else this hook does.
#
# `claim-check`'s `refined-this-session` rule compares an issue's tracker-minted
# `updatedAt` against this file's mtime: refinement must PREDATE the session that
# implements it. That predicate is only honest if the stamp marks the beginning
# of the session, so it is written here — above the provisioning steps, and above
# the `exit 1` a degraded container takes — rather than appended at the end. A
# session whose install failed still began, and a stamp written after the work
# would date the session to whenever the agent got round to claiming, which is
# exactly the ordering the rule exists to refuse.
#
# Silent and never fatal: this hook's job is setup, and a clone whose git dir is
# unwritable has larger problems than the claim gate. `claim-check` refuses on a
# MISSING stamp rather than passing, so a failure here fails closed downstream.
if stamp_dir=$(git rev-parse --git-dir 2>/dev/null) &&
	mkdir -p "$stamp_dir/batten-receipts" 2>/dev/null; then
	: >"$stamp_dir/batten-receipts/session-start" 2>/dev/null || true
fi

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

# The binary every hook registration executes (CLOUD-312). Built and INSTALLED
# here, in the synchronous provisioning window, for the same reason the steps
# above are: a fresh container has no `target/`, so without this a session would
# start with policy unenforced — a state the guards it replaced could not reach.
#
# `install:local` rather than `build:release` since CLOUD-824. The registrations
# used to name `.claude/hooks/batten-hook.sh`, a launcher whose four-candidate
# binary search let a session run with `target/release` and nothing else; they
# now name `batten` directly, as the other four harnesses always did, so the
# binary has to be somewhere PATH resolves. `install:local` puts it at
# `install.sh`'s own destination.
#
# THIS STEP IS NOW THE WHOLE "no binary" REPORT, and it is louder than what it
# replaces. The launcher failed open with a stderr line and a once-per-session
# `$TMPDIR` marker — the quietest report this repository produces. `step` emits
# `::error::`, the log pointer, and a non-zero exit, so a session that cannot
# mediate says so at the moment it could still be fixed rather than on the first
# tool call.
step batten-build mise run install:local

# The third per-clone step from AGENTS.md, performed at last (CLOUD-476).
#
# It used to be deliberately absent, and the reasoning was sound as far as it
# went: `hk install` writes `exec hk run pre-commit`, calling `hk` BARE, which
# resolves only where mise's shims are on PATH. In this environment they are
# not, so that hook makes every `git commit` fail with `hk: not found` —
# measured, on the very commit that added the step. A broken hook is worse than
# none, so the step was dropped and 24 commits in one container went through no
# gate at all.
#
# The answer is not to run `hk install` but to install a hook this repo owns:
# `.claude/hooks/git-hook` resolves `hk` through `mise exec --`, which is the
# form that works here, and refuses to re-enter a gate that is already running.
# Both properties are its own file's to explain; this step owns only the WHEN.
#
# A symlink, not a copy: a copy is a second authority that goes stale silently
# the moment the checked-in body changes, and `doctor` would keep passing over
# it. `-f` so a clone carrying hk's generated hook is repaired rather than
# skipped, which is the state every existing clone is in.
install_git_hooks() {
	local root hooks src name
	root=$(git rev-parse --show-toplevel) || return 1
	hooks=$(git rev-parse --git-path hooks) || return 1
	src="$root/.claude/hooks/git-hook"
	[ -x "$src" ] || {
		echo "no executable hook body at $src" >&2
		return 1
	}
	mkdir -p "$hooks" || return 1
	# Both hooks hk defines (hk.pkl `hooks`), through one body that dispatches on
	# the name it is invoked as. commit-msg carries the Conventional Commits
	# check that release-plz's semver depends on, so leaving it out would gate
	# the expensive half and not the one that decides a version.
	for name in pre-commit commit-msg; do
		ln -sfn "$src" "$hooks/$name" || return 1
	done
}
step git-hooks install_git_hooks
# The repo-local git identity, set before the session writes a line (CLOUD-274).
#
# It belongs in this window for the same reason `doctor` does: the vendor identity
# is injected at the environment level, so a fresh clone is already carrying it
# before any work starts, and the first thing that would notice is `commit-lint`
# refusing a branch whose commits are all already written. Setting it here means
# the gate has nothing to catch — feedforward that costs one idempotent git config
# read, rather than a refusal an agent has to unwind with a rebase.
#
# After `batten-build`, because this is the engine answering: the policy is
# `[attribution]` in batten.toml and `batten attribution identity` is what reads
# it. A WRITE, self-declared as one (house style §5), scoped to .git/config in
# this checkout — never --global, which covers a developer's own unrelated
# repositories. An identity a contributor set accountably is left exactly alone.
step attribution-identity mise run attribution-identity

# The not-signing posture, put into force in the same window and for the same
# reason (CLOUD-669). CLOUD-591 decided it — "the interim posture is not to
# sign" — and shipped no mechanism, so it was never once in force: the launcher
# writes `commit.gpgsign true` --global every session, and local beats global
# only if something writes local.
#
# The identity repair above and this are the same defect on two fields. The
# author field was gated and repaired; the SIGNATURE was neither, so every
# commit carried the environment's own key — one this repo does not hold, cannot
# publish, and which GitHub reports as `unknown_key`. `Attribution` has no
# signature field, so `identity_deny` structurally cannot see it.
#
# Before any commit is written, for the reason stated above: a repair that lands
# after the fact leaves signed commits that only a rebase can unwind.
step signing-posture mise run signing-posture --repair

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

# --- what was running when the container we replaced went down? ---------------
#
# CLOUD-451. The reclaim destroys a human's typed approval, and one mechanism has
# already been built against it and removed (CLOUD-515) because nobody could say
# whether occupancy was even the right lever. `reclaim-census` collects that
# evidence off `land-lock hold`'s existing beat; this is where it is read back.
#
# RECORD BEFORE READ, and the order is load-bearing: recording this boot after
# reading would make it part of the evidence it is being compared against.
#
# NEVER SETS `fail`, and deliberately not routed through `step`: a verdict about
# a past container is not a provisioning failure, and halting a session over one
# would be the sensor deciding something it has no business deciding. Only the
# positive reading speaks — exit 1 (idle when replaced) and exit 2 (cannot look)
# are silent, because a line every session start would be noise in the
# overwhelming case where nothing happened. Pointer-only: a verdict and two
# epochs, never a plan or a prompt body.
# Relative, because this script has already `cd`ed to the repo root above, and
# `CLAUDE_PROJECT_DIR` is only conditionally set, which `set -u` would fault on.
census="mise-tasks/reclaim-census"
if [ -x "$census" ]; then
	"$census" record-boot >/dev/null 2>&1 || true
	if verdict=$("$census" report 2>/dev/null); then
		echo "$verdict"
	fi
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "session-start: toolchain provisioned (mise install, submodules, doctor); container preflight clean"
