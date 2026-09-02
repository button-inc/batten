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
for _v in NO_PROXY no_proxy; do
  _cur="${!_v-}"
  case ",$_cur," in
    *,api.github.com,*) ;;
    *) export "$_v=api.github.com,objects.githubusercontent.com,codeload.github.com,uploads.github.com${_cur:+,$_cur}" ;;
  esac
done
if [[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]] && [[ -z "${MISE_GITHUB_TOKEN:-}" ]]; then
  export MISE_GITHUB_TOKEN="$GITHUB_PERSONAL_ACCESS_TOKEN"
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
