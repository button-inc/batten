#!/bin/bash
# The container's Setup script, committed so it can be reviewed and gated.
#
# WHY THIS FILE EXISTS IN THE REPOSITORY (CLOUD-1324). The hosting platform
# provisions a container from a single "Setup script" field and a single
# "Environment variables" field. A script that lives only in a text field is one
# nothing can review, nothing can diff, and nothing can check — so the container
# it produces is wrong in ways that only surface hours later, at whichever gate
# happens to need the missing thing first. Paste this file's contents into that
# field; the copy here is the one that gets read, changed and argued with.
#
# WHAT IT MAY AND MAY NOT DO. It provisions: mise, the pinned toolchain, host
# dependencies. It states no policy and repairs no environment drift — that is
# `[[startup]]`'s job in `batten.toml`, where each precondition is a check with
# an exit code and a repair, and where a reader can see them. The last step here
# runs those rows with `--repair`, which is the one place this script is allowed
# to change the environment, and it says so on the command line.
#
# Idempotent; safe to re-run.
set -uo pipefail

# The agent proxy re-terminates TLS; make curl trust its CA explicitly.
[[ -n "${SSL_CERT_FILE:-}" ]] && [[ -f "${SSL_CERT_FILE}" ]] && export CURL_CA_BUNDLE="${SSL_CERT_FILE}"

# 1. mise itself -> ~/.local/bin/mise (pin with MISE_VERSION=... to lock it).
export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
command -v mise >/dev/null 2>&1 || curl -fsSL https://mise.run | sh
command -v mise >/dev/null 2>&1 || {
	echo "setup: mise install failed" >&2
	exit 0
}

# ---------------------------------------------------------------------------
# 2. NO WRAPPER (CLOUD-2688). This step used to shadow mise with a wrapper that
#    fenced the GitHub hosts out of the agent proxy and fed mise a session PAT,
#    because an UNLOCKED install resolves every tool through api.github.com and
#    the proxy refuses that for third-party repos. There is no PAT — the
#    container carries only the proxy's `proxy-` placeholders — and the API is
#    not needed: every install below is LOCKED, from the URL and checksum
#    `mise.lock` pins, which the proxy serves. Measured 2026-11-11: the whole
#    manifest installed that way into an empty data directory, lock unchanged.
#
#    A container an earlier run set up still has the wrapper; put the real
#    binary back so nothing fences.
# ---------------------------------------------------------------------------
MISE_BIN="$HOME/.local/bin/mise"
MISE_REAL="$HOME/.local/libexec/mise"
if [[ -x "$MISE_REAL" ]] && ! grep -qa ELF <<<"$(head -c4 "$MISE_BIN" 2>/dev/null || true)"; then
	mv -f "$MISE_REAL" "$MISE_BIN"
fi
export MISE_LOCKFILE=true MISE_LOCKED=true

# 3. Interactive shells still get full activation ([env] blocks, task env), so
#    .bashrc need only add PATH + activate.
if ! grep -q 'mise activate bash' "$HOME/.bashrc" 2>/dev/null; then
	cat >>"$HOME/.bashrc" <<'EOF'

# mise — shims first so non-interactive shells and git hooks resolve pinned tools.
export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
command -v mise >/dev/null 2>&1 && eval "$(mise activate bash)"
EOF
fi

# 4. Provision every committed mise config, root first, then any nested ones.
#    Locked (step 2), so provisioning needs no GitHub API and no credential.
#
#    `CLAUDE_PROJECT_DIR` is read as a HINT and never required: it is one
#    harness's spelling, and this script must work under any of them. `$PWD` is
#    the answer everywhere else, and the platform runs setup in the checkout.
cd "${CLAUDE_PROJECT_DIR:-$PWD}" || exit 0
mise trust --all >/dev/null 2>&1
mise install --yes || echo "setup: root 'mise install' incomplete — see output above" >&2
git ls-files -- '*mise.toml' '.tool-versions' 2>/dev/null |
	xargs -r -n1 dirname | sort -u | grep -v '^\.$' |
	while read -r d; do
		(cd "$d" && mise install --yes) ||
			echo "setup: 'mise install' incomplete in $d" >&2
	done

# 5. Create the shims. Without this the shims directory is EMPTY, every tool
#    resolves to the image's unpinned copy, and `mise ls --current` still looks green.
mise reshim

# 6. Host dependencies mise does not provision (PDFium, NSS tools, the native
#    binaries). PDFium's absence makes a determinism test fail, so this belongs in
#    setup rather than at first use.
mise run deps-install || echo "setup: 'deps-install' incomplete — see output above" >&2

# 6a. SUPERSEDE THE CONSUMER ARTIFACT WITH THIS CLONE'S OWN BUILD (CLOUD-1859).
#
#     `deps-install` runs `install.sh`, which resolves `-musl` for every Linux
#     host deliberately — "the one that runs on any Linux whatever its glibc
#     version" (`install.sh:136`). That is right for a CONSUMER and wrong for this
#     container, because the binary it drops on PATH is the one every harness hook
#     spawns on every single tool call.
#
#     Measured 2026-09-19, same version, same tree, same box, warm and repeated:
#
#       operation                     musl       gnu    ratio
#       adjudicate (every tool call) 1444ms     96ms    15.0x
#       check --rule                  506ms     93ms     5.4x
#       check (143 rules)           15501ms   1791ms     8.7x
#
#     Both emit byte-identical output and exit 0, so this is not two programs
#     doing different work. `strace -c` names the mechanism rather than leaving it
#     to inference: 5779 syscalls against 362, of which 2728 `mmap` and 2718
#     `munmap` — 94% of the calls and 97% of the syscall time — which is mallocng
#     returning freed memory to the OS on every free where glibc retains arenas.
#
#     `install:local` is the task that already exists for this, "a dev-clone
#     convenience that supersedes a release build" (`mise.toml:2444`), writing to
#     `install.sh`'s own destination character for character. Until now nothing
#     invoked it.
#
#     HERE RATHER THAN IN `deps-install`, because that task's own comment is right
#     that a provisioning path "cannot assume a Rust toolchain, a 141-second
#     compile, or that the checkout builds at all" (CLOUD-1085). This script
#     installs the pinned toolchain at step 4, so the assumption holds at this
#     line and only here. That task is also one line under a `non_increasing`
#     ratchet, so growing its body is refused regardless.
#
#     Soft-failed like its neighbours: a clone that cannot build still has the
#     musl binary `deps-install` installed, which works and is merely slower.
#
#     The CONSUMER-side question — whether `install.sh` should prefer `-gnu`
#     where glibc is present — is CLOUD-1861 and is deliberately not decided here.
mise run install:local ||
	echo "setup: 'install:local' incomplete — the slower musl build stays on PATH" >&2

# 6b. THE ONE FACT ONLY THIS ENVIRONMENT CAN STATE (CLOUD-1383).
#
#     Batten repairs the surfaces it owns — the harness hook registrations it
#     derives — and whether a repair may REMOVE what it finds is not a property of
#     the finding. The census is equally right on a disposable container and on a
#     developer's laptop; what differs is whose `$HOME` it is. So the environment
#     states it, in the platform's one Environment variables field:
#
#         BATTEN_ENVIRONMENT=disposable
#
#     ABSENT IS THE DEFAULT AND MEANS A REAL MACHINE, which is the direction that
#     has to be safe: a developer who never sets it gets a batten that reports and
#     never removes, and a container whose field was mistyped gets the same — a
#     stalled repair rather than a surprise deletion.
#
#     Checked here rather than assumed, because the failure is silent otherwise:
#     an unset variable leaves every session's repair conservative, the launcher's
#     registrations survive, and the wiring gate refuses with a remedy no verb
#     performs. That is the exact class this script exists to make visible at
#     setup rather than three tasks later.
if [[ "${BATTEN_ENVIRONMENT:-}" != "disposable" ]]; then
	echo "setup: BATTEN_ENVIRONMENT is not 'disposable' — environment repairs will REPORT" >&2
	echo "setup: and never remove. If this container's home directory is provisioned per" >&2
	echo "setup: session, add BATTEN_ENVIRONMENT=disposable to the Environment variables" >&2
	echo "setup: field. If this is a real machine, this is the correct posture." >&2
fi

# 7. THE DECLARED PRECONDITIONS, REPAIRED. Every `[[startup]]` row in batten.toml
#    is checked, repaired if it declares a repair, and re-checked; the report is
#    one pointer line per row. `--repair` is why this line is allowed to change
#    anything, and it is spelled out rather than implied so that a reader of the
#    setup log can see where the environment was mutated.
#
#    Non-blocking: a row that cannot be repaired here is reported again on the
#    advisory channel at every session start, where an agent will actually read
#    it. A setup script that exited non-zero would take the container down over a
#    precondition the session could still fix.
mise exec -- batten startup --repair ||
	echo "setup: some declared preconditions are unmet — see the lines above" >&2

# 8. Report, so a failure is visible in the setup log and not at first use.
mise ls --current || true
mise run deps || true
exit 0
