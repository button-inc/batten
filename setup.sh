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
# 2. GitHub reachability behind the agent proxy — a PATH WRAPPER, not an env file.
#
#    mise resolves every tool release through api.github.com. The proxy injects a
#    token scoped to THIS repo only, so that host answers 403 for third-party tool
#    repos (uv, cargo-deny, release-plz). The fix is to send the API + asset hosts
#    around the proxy via NO_PROXY and let mise authenticate with the session PAT.
#
#    WHY A WRAPPER AND NOT BASH_ENV / .bashrc / .env:
#      * The platform injects its OWN NO_PROXY (without api.github.com) as a real
#        process env var, so a static NO_PROXY in the env config is overwritten —
#        it MUST be mutated at runtime.
#      * An agent's shell tool typically runs each command in a fresh
#        non-interactive, non-login bash that sources NEITHER BASH_ENV NOR
#        ~/.bashrc. So an env file, however early it is written, never reaches the
#        agent's own `mise` calls — only child processes it spawns.
#      * PATH starts with ~/.local/bin (writable, and where the real mise lives),
#        so a wrapper there is the one hook that intercepts EVERY mise invocation:
#        the agent shell, git hooks, cargo subprocesses, and `mise activate` alike.
#
#    The wrapper relocates the real binary to ~/.local/libexec/mise and shadows it
#    at ~/.local/bin/mise. It prepends the GitHub hosts to NO_PROXY (github.com
#    itself stays proxied, so git keeps its proxy auth to this repo) and sets
#    MISE_GITHUB_TOKEN from the session PAT (mise-only; the proxy's own
#    GITHUB_TOKEN for git is left untouched). Both are idempotent guards.
# ---------------------------------------------------------------------------
MISE_BIN="$HOME/.local/bin/mise"
MISE_LIBEXEC="$HOME/.local/libexec"
MISE_REAL="$MISE_LIBEXEC/mise"
mkdir -p "$MISE_LIBEXEC"

# If ~/.local/bin/mise is the real ELF binary (freshly installed, or replaced by a
# mise self-update / re-run of mise.run), move it under libexec. head -c4 on an ELF
# begins with 0x7F,'E','L','F'; -a lets grep read the binary as text.
#
# READ THEN MATCH, never piped. `head … | grep -q` under `pipefail` reports the
# PIPELINE's failure when grep exits early on a match and head takes SIGPIPE — so
# a MATCH reads as false and the relocation silently never happens, which is the
# one branch this block exists for. `pipefail-grep-check` names the class.
mise_magic="$(head -c4 "$MISE_BIN" 2>/dev/null || true)"
if [[ -f "$MISE_BIN" ]] && grep -qa ELF <<<"$mise_magic"; then
	mv -f "$MISE_BIN" "$MISE_REAL"
fi

# (Re)write the wrapper every run so fixes to it always take effect.
cat >"$MISE_BIN" <<'WRAP'
#!/usr/bin/env bash
# mise wrapper: guarantee GitHub reachability behind the agent proxy for EVERY
# mise call, independent of shell init. See setup.sh for the full rationale.
# BOTH HALVES ARE REQUIRED, AND THE FIRST ONE IS `NO_PROXY` (CLOUD-1474).
# Measured 2026-09-06 over `mise ls-remote aqua:EmbarkStudios/cargo-deny`, with
# `mise cache clear` BEFORE EACH ARM — without that the first arm to succeed
# makes every later arm pass from cache, which is how the previous revision of
# this comment came to assert the opposite of the table below:
#
#   NO_PROXY prepended, no explicit token                401
#   proxy on, NO_PROXY untouched, no token               403
#   proxy on, NO_PROXY untouched, + MISE_GITHUB_TOKEN    403
#   NO_PROXY prepended + MISE_GITHUB_TOKEN=<pat>         OK, 100 versions
#
# Rows 3 and 4 differ only in NO_PROXY, so `mise` DOES honour it — the claim that
# it does not was the error, and `unset HTTPS_PROXY` was the remedy built on it.
# Row 4 succeeds with HTTPS_PROXY still set, so the unset buys nothing: it is the
# same fence applied to every host instead of the four that need it, and it
# strips the proxy from every process `exec` hands it to — cargo, rustup, uv,
# npm and every task body — which is what /root/.ccr/README.md and house policy
# both refuse.
#
# WHY ROW 1 IS A 401 AND NOT AN AUTH-FREE SUCCESS — this is the whole bug. The
# container injects a PLACEHOLDER `GITHUB_TOKEN` (its value literally begins
# `proxy-`). Proxied, that never reaches GitHub, because the proxy substitutes
# its own credential; fenced out via NO_PROXY, mise sends the placeholder direct
# and GitHub rejects it. So the fence turned a 403 into the reported 401 and the
# two failures are the same missing token seen from either side of the proxy.
# `mise.toml`'s `[env]` block has recorded this in as many words all along.
#
# The proxy DOES substitute: through it, our PAT, the ambient GITHUB_TOKEN, a
# made-up string and NO Authorization header all return the same identity and the
# same 15000/hr limit. Direct, no header returns 60 and our PAT returns 5000.
# The no-header arm is the discriminator — unauthenticated GitHub is 60/hr, so
# 15000 with no credential sent can only be the proxy answering.
#
# `github.com` is deliberately NOT fenced, so git keeps its proxy-provided auth
# to this repo; only the API and asset hosts go direct.
for _v in NO_PROXY no_proxy; do
  _cur="${!_v-}"
  case ",$_cur," in
    *,api.github.com,*) ;;
    *) export "$_v=api.github.com,objects.githubusercontent.com,codeload.github.com,uploads.github.com${_cur:+,$_cur}" ;;
  esac
done

# THE TOKEN'S NAME IS THE OTHER HALF. This read only
# GITHUB_PERSONAL_ACCESS_TOKEN; the container injects BATTEN_GITHUB_TOKEN, and
# neither that name nor MISE_GITHUB_TOKEN was set — so mise fell through to the
# placeholder above. First-set wins, so an explicit MISE_GITHUB_TOKEN — what
# mise-action sets in CI — is never overwritten. `GH_TOKEN` is NOT a name mise
# reads: setting only that still 401s (measured), so it must be this variable.
if [[ -z "${MISE_GITHUB_TOKEN:-}" ]]; then
  for _t in GITHUB_PERSONAL_ACCESS_TOKEN BATTEN_GITHUB_TOKEN; do
    if [[ -n "${!_t-}" ]]; then
      export MISE_GITHUB_TOKEN="${!_t}"
      break
    fi
  done
fi
exec "$HOME/.local/libexec/mise" "$@"
WRAP
chmod +x "$MISE_BIN"

# If the real binary somehow is not in place (fresh box where mise.run wrote the
# wrapper's path, or a wiped libexec), reinstall it and relocate once more.
if [[ ! -x "$MISE_REAL" ]]; then
	curl -fsSL https://mise.run | MISE_INSTALL_PATH="$MISE_REAL" sh ||
		echo "setup: could not provision the real mise binary" >&2
fi

# 3. Interactive shells still get full activation ([env] blocks, task env). The
#    wrapper already covers the proxy/PAT, so .bashrc need only add PATH + activate.
if ! grep -q 'mise activate bash' "$HOME/.bashrc" 2>/dev/null; then
	cat >>"$HOME/.bashrc" <<'EOF'

# mise — shims first so non-interactive shells and git hooks resolve pinned tools.
# GitHub-proxy reachability + PAT are handled by the ~/.local/bin/mise wrapper.
export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
command -v mise >/dev/null 2>&1 && eval "$(mise activate bash)"
EOF
fi

# 4. Provision every committed mise config, root first, then any nested ones.
#    Every `mise` below is the wrapper, so provisioning works with no manual env.
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
