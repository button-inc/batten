#!/usr/bin/env bash
#MISE description="Gate: the provisioning mise does NOT own — the bats submodule and the rustup cross targets — is present and consistent. Repairs what it can."
#
# `mise install` provisions [tools] and nothing else. Two dependencies of the
# lifecycle sit outside it, and both fail LATE and in someone else's name:
#
#   * bats lives in the tests/bats submodule (see mise.toml [env], which explains
#     why it is vendored rather than pinned). A fresh clone that skipped
#     `git submodule update --init` reaches `test:bats` and reports
#     "bats: not found" — a missing checkout wearing a missing-tool costume.
#   * the cross targets come from rustup, whose `add` is not idempotent against a
#     half-installed component (see doctor-check). Surfaces as a rollback inside
#     cross-check or darwin-link, minutes in, looking like a build failure.
#
# Neither is a code defect and neither is discoverable from the message it
# prints, which is what makes them expensive: the first read of both is "the
# branch broke something". `verify` depends on this task so the environment is
# asserted BEFORE the long steps run, and the assertion is the same one in every
# clone instead of a paragraph of setup prose nobody re-reads.
#
# It repairs rather than only reporting. These are provisioning steps with one
# correct outcome — a checked-out submodule, an installed target — so a diagnosis
# the caller must hand-translate into commands is just a slower version of the
# fix. Repairs are idempotent and touch only the toolchain and the submodule,
# never the working tree.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The targets the LOCAL lifecycle needs: cross-check type-checks the Windows
# triple, darwin-link links the Darwin one. This matches CI, whose darwin-link
# matrix also carries aarch64 alone — x86_64-apple-darwin is linked in
# release-artifacts.yml, where a real artifact is produced. Pulling a second
# Darwin std here would cost every local verify a download nothing then uses.
# `-` and not `:-`, so an explicitly EMPTY DOCTOR_TARGETS means "no rust targets
# needed" rather than falling back to the default pair. CI's `ci` job wants
# exactly that: it runs test:bats, which needs the submodule half of this task
# and none of the rustup half, since cross-check and darwin-link are their own
# jobs. With `:-` there is no way to ask for zero targets. `--no-targets` is
# the same request as a CLI flag, so a task dependency can ask for it without
# reaching through the environment (test:bats does, in mise.toml).
if [[ "${1:-}" = "--no-targets" ]]; then
	DOCTOR_TARGETS=""
fi
read -r -a targets <<<"${DOCTOR_TARGETS-x86_64-pc-windows-gnu ${DARWIN_TARGET:-aarch64-apple-darwin}}"

# --- concurrency: doctor races itself, by design of the task graph -------------
#
# `verify` reaches this task twice in one invocation — through `cross-check`, and
# again through `ci` -> `hooks` -> `hk check --all`, whose `test:bats` step shells
# out to `mise run test:bats`. That is a SEPARATE mise process, so the dependency
# dedup that would collapse the two nodes never sees the second one (CLOUD-201).
#
# The rustup half is already safe: every target goes through `target-ensure`,
# which holds a per-toolchain lock. The two REPAIRS are the writers that were
# left. Concurrent `git submodule update` calls race git's index lock, and two
# torn-install repairs let one doctor `rm -rf` the version directory the other's
# `mise install` is populating — manufacturing the exact CLOUD-182 tear this task
# exists to fix.
#
# One lock covers both, deliberately: two locks is two acquisition orders, and
# both repairs are provisioning writes. It lives beside the `installs/` tree it
# guards rather than in the working tree — an untracked lock directory there
# would make `tree-clean` refuse every `verify` (CLOUD-277).
#
# Each repair CHECKS OUTSIDE the lock and RE-CHECKS INSIDE it, `target-ensure`'s
# idiom: the healthy path never takes the lock at all, and a doctor that queued
# behind the winner re-reads fresh state and no-ops instead of repeating the
# repair or reporting one it did not do.
lock="${MISE_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/mise}/.batten-doctor-lock"
with_lock="$(dirname "$0")/with-lock.sh"
installs="${MISE_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/mise}/installs"

broken_bins() { # bin symlinks whose target does not exist (portable: no -xtype)
	find "$installs" -mindepth 4 -maxdepth 4 -path '*/bin/*' -type l 2>/dev/null |
		while IFS= read -r link; do [[ -e "$link" ]] || printf '%s\n' "$link"; done
}

repair_submodule() {
	if [[ -x tests/bats/bin/bats ]]; then
		echo "doctor: bats submodule checked out"
		return 0
	fi
	echo "doctor: tests/bats not checked out — running git submodule update --init"
	git submodule update --init --recursive tests/bats
	if [[ -x tests/bats/bin/bats ]]; then
		echo "doctor: bats submodule checked out"
		return 0
	fi
	echo "::error:: tests/bats is still missing after submodule update; test:bats cannot run." >&2
	return 1
}

# Torn mise installs (CLOUD-182). `mise install` trusts its own record: a version
# directory whose payload is gone still counts as installed, `mise install`
# no-ops on it, and the first symptom is an exec failure wearing someone else's
# name — measured here as bin/serena a broken symlink into an absent venv while
# `mise ls` reported 1.6.1, so the Serena MCP server silently never connected.
# Check the ARTIFACTS, not the record: a bin entry that is a broken symlink marks
# that tool version as torn. Repair by removing the version directory and
# re-running `mise install`, which reprovisions whatever mise.toml says is
# missing — no fragile mapping from a directory name back to tool syntax.
repair_installs() {
	local torn vdir
	torn=$(broken_bins | sed -E 's|/bin/[^/]+$||' | sort -u)
	if [[ -z "$torn" ]]; then
		echo "doctor: mise installs intact (no broken bin symlinks)"
		return 0
	fi
	while IFS= read -r vdir; do
		echo "doctor: torn install (broken bin symlink) — removing $vdir"
		rm -rf -- "$vdir"
	done <<<"$torn"
	echo "doctor: re-running mise install to reprovision"
	if ! mise install; then
		echo "::error:: mise install failed after removing torn installs" >&2
		return 1
	fi
	if [[ -n "$(broken_bins | head -n1)" ]]; then
		echo "::error:: torn install remains after repair: $(broken_bins | head -n1)" >&2
		return 1
	fi
	echo "doctor: torn installs reprovisioned"
}

# The repair modes, dispatched FIRST and before any other work: this script
# re-enters itself under the lock so each repair's re-check happens inside the
# critical section, and a repair child must do its repair and nothing else. A
# dispatch placed lower would have the child re-run the outer flow and queue for
# a lock its own parent holds.
case "${1:-}" in
--repair-submodule)
	repair_submodule
	exit
	;;
--repair-installs)
	repair_installs
	exit
	;;
esac

export WITH_LOCK_LABEL="the doctor provisioning lock"
status=0

# --- the bats submodule -------------------------------------------------------

if [[ -x tests/bats/bin/bats ]]; then
	echo "doctor: bats submodule checked out"
elif ! "$with_lock" "$lock" -- "$0" --repair-submodule; then
	status=1
fi

# --- the git hooks (CLOUD-476) ------------------------------------------------
#
# `hk install` is the per-clone step nothing performed and nothing asserted, so
# every commit in a cloud container bypassed the gate — measured at 24 of them,
# one carrying a ShellCheck failure that rode all the way to `verify`.
# `session-start.sh` performs it now; this decides it, in the same
# perform-then-assert split the bats submodule already uses.
#
# IT MUST BE ABLE TO RUN, NOT MERELY EXIST: "present but cannot resolve `hk`" is
# the exact failure the old deferral was written to avoid, and a file-existence
# check reports it as healthy.
#
# BUT IT IS PROBED, NEVER RUN. This task runs INSIDE the gate (`test:bats`
# depends on it), so executing a hook that runs the gate re-enters it —
# unbounded recursion, measured as a hung `git commit`. So the contract is read
# first: a hook that honours `BATTEN_HOOK_PROBE` can be asked the narrow
# question ("does `hk` resolve here") for one cheap call, and a hook that does
# not is REPORTED, never executed. That ordering is the whole safety property —
# executing an unknown hook from here is the hang.
#
# NOT ASSERTED UNDER CI, and that is not a weakening: a CI checkout never runs
# `git commit`, so it has no commit path to gate — it runs the gate directly, as
# `mise run ci`. Asserting a hook there would fail every job over the absence of
# a mechanism that job does not use, which is a gate reporting on the wrong
# object.
if [[ -n "${BATTEN_HOOK_PROBE:-}" ]] || [[ -n "${CI:-}" ]]; then
	# Already inside a probe (or in CI): the outer caller owns this verdict, and
	# asking it again from here would be the second half of the same recursion.
	:
else
	for hook_name in pre-commit commit-msg; do
		hook="$(git rev-parse --git-path "hooks/$hook_name")"
		if [[ ! -x "$hook" ]]; then
			# printf, not echo: the remedy is a path and a command, and pointer-only
			# either way — never a byte of the hook body.
			printf '::error:: no executable %s hook at %s — commits in this clone bypass the gate. Do: run .claude/hooks/session-start.sh, or symlink it to .claude/hooks/git-hook.sh\n' \
				"$hook_name" "$hook" >&2
			status=1
		elif ! grep -q BATTEN_HOOK_PROBE "$hook" 2>/dev/null; then
			printf '::error:: the %s hook at %s does not honour BATTEN_HOOK_PROBE, so it cannot be checked from inside the gate without recursing. It was NOT run. Replace it with .claude/hooks/git-hook.sh (run .claude/hooks/session-start.sh)\n' \
				"$hook_name" "$hook" >&2
			status=1
		elif ! BATTEN_HOOK_PROBE=1 "$hook" </dev/null >/dev/null 2>&1; then
			printf '::error:: the %s hook at %s cannot resolve its runner in this environment, so every commit would fail wearing a missing-tool costume. Do: mise install\n' \
				"$hook_name" "$hook" >&2
			status=1
		else
			echo "doctor: $hook_name hook installed and runnable"
		fi
	done
fi

# --- the rustup cross targets -------------------------------------------------
#
# The classify/purge/add sequence lives in `target-ensure`, which serializes
# every toolchain mutation behind one per-toolchain lock (CLOUD-220): a second
# doctor — hk's test:bats step re-runs this task in a child mise process, which
# dedupes task nodes only within one process — or a concurrent darwin-link
# queues there instead of colliding with this one inside `rustup target add`.

ensure="$(dirname "$0")/target-ensure.sh"

for target in "${targets[@]}"; do
	if ! "$ensure" "$target"; then
		echo "::error:: could not install rust target $target; cross-check/darwin-link will fail." >&2
		status=1
	fi
done

# --- torn mise installs (CLOUD-182) -------------------------------------------
#
# Why the check reads artifacts rather than mise's record is written once, beside
# `repair_installs` above. The scan runs here, unlocked, so an intact tree — the overwhelmingly common
# case — costs no lock at all. Only a tree that looks torn queues, and the
# re-scan inside the critical section is what stops the second doctor removing
# and reprovisioning what the first one has already repaired.
if [[ -d "$installs" ]]; then
	if [[ -z "$(broken_bins | head -n1)" ]]; then
		echo "doctor: mise installs intact (no broken bin symlinks)"
	elif ! "$with_lock" "$lock" -- "$0" --repair-installs; then
		status=1
	fi
fi

[[ "$status" -eq 0 ]] && echo "doctor: environment consistent"
exit "$status"
