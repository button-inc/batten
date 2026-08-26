#!/bin/sh
#
# Claude cloud container setup: get the released `batten` on PATH before the
# session starts.
#
# WHY THIS LIVES UNDER `.claude/`. It is the one harness-specific piece of this
# arrangement, so it sits with the rest of the Claude material rather than in a
# neutral directory — everything it calls (`install.sh`, the release assets) is
# harness- and OS-agnostic and stays that way. A second harness that needs the
# same thing writes its own four-line caller here and reuses all of it.
#
# WHY IT IS IN THE REPO AT ALL, given the container's own start script is where it
# runs. That console field cannot be version controlled: nobody can review it,
# `contract-drift` cannot see it, and no gate reads it. So the steps live here with
# a history, and the field holds one line that calls this. What is out of tree is a
# pointer, not a program.
#
# WHAT IT FIXES, measured rather than assumed. `.claude/settings.json` registers
# `batten hook --harness claude-code` on `SessionStart` as the FIRST group, ahead
# of `.claude/hooks/session-start.sh` — and that hook is what runs
# `mise run install:local`, the step that puts the binary on PATH. So on a cold
# container the engine's own `SessionStart` registration fires with no binary. It
# fails open, quietly, which means the `contract-drift` snapshot that is supposed
# to be seeded "before any tool does" is not seeded at all on a fresh container,
# and nothing reports it. This is what makes that registration find a binary.
#
# ONE JOB: the binary. `mise install`, the submodules, `doctor`, the git hooks and
# `container-preflight` all stay in `session-start.sh`, where they are gated, are
# covered by `tests/session-start.bats`, and are visible to `contract-drift`.
# `session-start.sh` also still runs `install:local`, which is not redundant: on a
# dev clone the working tree's build must supersede the released binary, and it is
# the recovery path if this never ran.
#
# IT ASSUMES NO CHECKOUT AND NO PARTICULAR REPOSITORY. It reads no path relative to
# a working tree, so a container that checks out something else, several things, or
# nothing at all is a container this still works on. `BATTEN_VERSION` pins which
# release to install, and a caller that fetched THIS script from a release tag
# should pass that same tag, so the bootstrap and the binary it installs come from
# one tested release rather than from two.
#
# Idempotent: safe to re-run. A second run re-installs the same version over the
# same path, which is how `install.sh` already behaves.
#
# Exit 0 installed / 1 refused / 2 could not look — house-style §7, the same
# spelling `install.sh` and `release-assets-check` use.
set -eu

REPO="${BATTEN_REPO:-button-inc/batten}"
API="${BATTEN_API:-https://api.github.com}"
# Somewhere on PATH, and that is load-bearing: `install.sh` only WARNS on stderr
# when its destination is off PATH, so getting this wrong installs a binary
# nothing can find and says so only in a log nobody reads.
DEST="${BATTEN_INSTALL_DIR:-/usr/local/bin}"
LOG="${BATTEN_BOOTSTRAP_LOG:-/tmp/container-setup-batten.log}"
RETRIES="${BATTEN_BOOTSTRAP_RETRIES:-3}"

log() { printf '%s\n' "$*" >>"$LOG"; }
die() {
	printf 'container-setup: %s\n' "$2" >&2
	log "$2"
	exit "$1"
}

# THE GITHUB HOSTS MUST BE FENCED IN THE AMBIENT `NO_PROXY`, and nothing inside
# the repo can do it for us. `mise.toml`'s `[env]` appends exactly these, but
# `container-preflight` records why that cannot help: mise applies `[env]` to the
# processes it RUNS, after its own resolver has already made the call. Same shape
# one layer earlier — `install.sh` inherits whatever the container exports, so an
# unfenced `api.github.com` sends the release read through a proxy and the whole
# thing exits 2 having installed nothing.
for host in api.github.com objects.githubusercontent.com codeload.github.com uploads.github.com; do
	case ",${NO_PROXY:-}," in
	*",$host,"*) ;;
	*) NO_PROXY="${NO_PROXY:+$NO_PROXY,}$host" ;;
	esac
done
no_proxy="$NO_PROXY"
export NO_PROXY no_proxy

command -v curl >/dev/null 2>&1 || die 2 "no curl, so no release can be read."
command -v tar >/dev/null 2>&1 || die 2 "no tar, so install.sh could not unpack an archive."

# WHICH TOKEN THIS HOST'S RELEASE READS NEED, which is host knowledge and so
# belongs here rather than in the generic installer. Measured on a Claude cloud
# container: `GH_TOKEN` and `GITHUB_TOKEN` are both set and both answer **401** on
# `api.github.com` for this PRIVATE repo, while `GITHUB_PERSONAL_ACCESS_TOKEN`
# succeeds. `install.sh` prefers the first non-empty of its list, so leaving this
# to it would send the 401 one and stop.
#
# Naming it through `BATTEN_GITHUB_TOKEN` is how a host declares the answer — the
# installer's own precedence is untouched, and it keeps working unchanged the day
# CLOUD-585 makes the repo public and no token is needed at all.
if [ -z "${BATTEN_GITHUB_TOKEN:-}" ] && [ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]; then
	BATTEN_GITHUB_TOKEN="$GITHUB_PERSONAL_ACCESS_TOKEN"
	export BATTEN_GITHUB_TOKEN
	log "using GITHUB_PERSONAL_ACCESS_TOKEN for the release read"
fi

# THE RELEASE IS THE SOURCE, AND A CHECKOUT IS NEVER TRUSTED IMPLICITLY. An
# earlier version of this preferred a checked-out `install.sh` when it found one,
# and that was wrong twice over: a container may check out any repository, or
# several, or none, so there is nothing to resolve a path against; and whatever IS
# checked out is an arbitrary ref — a feature branch, a fork, an unreviewed PR head
# — so running its bootstrap means a session on any branch installs whatever that
# branch says to. The whole point of pinning to a RELEASE is that a release is
# tested and immutable and a branch tip is neither.
#
# So the fetch path is the only path, and the script's own bytes are verified
# against the release's checksum manifest before anything runs: piping an
# unverified script into a shell moves the trust boundary rather than holding it.
# `install.sh` is a release asset for exactly this, and `release-assets-check` is
# the gate that keeps it one.
#
# `BATTEN_SETUP_FROM_CHECKOUT=1` opts INTO the local file, for a maintainer testing
# an unreleased change. Opt-in rather than detected, because the safe default has to
# be the one a container gets without anyone choosing it.
if [ "${BATTEN_SETUP_FROM_CHECKOUT:-0}" = "1" ]; then
	here=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
	[ -x "$here/install.sh" ] || die 2 "BATTEN_SETUP_FROM_CHECKOUT=1 but no executable install.sh beside $here — this opt-in names a checkout that is not there."
	log "opted into the checked-out install.sh at $here/install.sh"
	BATTEN_INSTALL_DIR="$DEST" BATTEN_REPO="$REPO" BATTEN_API="$API" \
		sh "$here/install.sh" >>"$LOG" 2>&1 ||
		die $? "install.sh refused or could not complete — see $LOG."
else
	log "fetching install.sh from the release"

	# One retry policy, here, because `install.sh` deliberately has none: it runs
	# curl with `silent show-error fail location` and no `--retry`, no
	# `--connect-timeout` and no `--max-time`, so a caller is the only place a
	# transient failure can be absorbed. Backoff rather than a tight loop — a
	# rate-limited release API answers no faster for being asked again at once.
	# THE TOKEN TRAVELS ON STDIN, never in argv — an `Authorization: Bearer …` on
	# the command line is readable by any other user on the box through `ps`, which
	# is the same reason `install.sh` uses `curl --config -`. Sending it at all is
	# not optional on a private repo: the first version of this fallback set
	# `BATTEN_GITHUB_TOKEN` for the installer and then made its OWN release read
	# unauthenticated, which answers 403 and reads exactly like an egress problem.
	fetch() { # fetch <url> <dest>
		attempt=1
		while :; do
			if {
				if [ -n "${BATTEN_GITHUB_TOKEN:-}" ]; then
					printf 'header = "Authorization: Bearer %s"\n' "$BATTEN_GITHUB_TOKEN"
				fi
				printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
				printf 'silent\nshow-error\nfail\nlocation\n'
				printf 'connect-timeout = 10\nmax-time = 120\n'
				printf 'output = "%s"\n' "$2"
				printf 'url = "%s"\n' "$1"
			} | curl --config -; then
				return 0
			fi
			[ "$attempt" -ge "$RETRIES" ] && return 1
			sleep $((attempt * attempt))
			attempt=$((attempt + 1))
		done
	}

	scratch=$(mktemp -d) || die 2 "no writable temp directory."
	trap 'rm -rf "$scratch"' EXIT

	# The release resolved ONCE and reused, so the manifest and the script cannot
	# come from two different releases — which is the one way a verified script
	# could still be the wrong script.
	if [ -n "${BATTEN_VERSION:-}" ]; then
		rel_url="$API/repos/$REPO/releases/tags/${BATTEN_VERSION}"
	else
		rel_url="$API/repos/$REPO/releases/latest"
	fi
	fetch "$rel_url" "$scratch/release.json" || die 2 "cannot read the release list at $rel_url."

	# No jq: this runs before anything is provisioned, the same constraint
	# `install.sh` is written under.
	asset_url() { # asset_url <name-pattern>
		tr ',' '\n' <"$scratch/release.json" |
			grep -F '"browser_download_url"' |
			sed -nE 's#.*"(https://[^"]*/'"$1"')".*#\1#p' |
			head -n 1
	}

	sums_url=$(asset_url 'SHA256SUMS[A-Za-z0-9._-]*')
	[ -n "$sums_url" ] || die 1 "the release carries no checksum manifest, so install.sh cannot be verified."
	script_url=$(asset_url 'install\.sh')
	[ -n "$script_url" ] || die 1 "the release carries no install.sh asset. release-assets-check is the gate that should have caught this."

	fetch "$sums_url" "$scratch/SHA256SUMS" || die 2 "cannot fetch the checksum manifest."
	fetch "$script_url" "$scratch/install.sh" || die 2 "cannot fetch install.sh."

	if command -v sha256sum >/dev/null 2>&1; then
		got=$(sha256sum "$scratch/install.sh" | cut -d' ' -f1)
	elif command -v shasum >/dev/null 2>&1; then
		got=$(shasum -a 256 "$scratch/install.sh" | cut -d' ' -f1)
	else
		die 2 "no sha256sum or shasum, so install.sh cannot be verified — and this does not run unverified bytes."
	fi

	# `sha256sum`'s own format: 64 hex, a space, a mode byte, the name. Anchored on
	# the basename so a manifest listing paths and one listing names both read.
	want=$(sed -nE 's/^([0-9a-fA-F]{64}) [ *].*install\.sh$/\1/p' "$scratch/SHA256SUMS" | head -n 1)
	[ -n "$want" ] || die 1 "the manifest has no entry for install.sh, so its bytes are unverified. Nothing was run."
	[ "$got" = "$want" ] || die 1 "sha256 mismatch on install.sh — the manifest and the script disagree. Nothing was run."
	log "fetched install.sh verified against the release manifest"

	BATTEN_INSTALL_DIR="$DEST" BATTEN_REPO="$REPO" BATTEN_API="$API" \
		sh "$scratch/install.sh" >>"$LOG" 2>&1 ||
		die $? "install.sh refused or could not complete — see $LOG."
fi

# The one thing worth asserting rather than assuming: the binary is where a bare
# `batten` will find it. Every hook registration names it bare, so a binary
# installed off PATH is indistinguishable from no binary at all.
command -v batten >/dev/null 2>&1 ||
	die 1 "batten installed into $DEST but is not resolvable as \`batten\` — $DEST is not on PATH, and every hook registration names it bare."

printf 'container-setup: batten ready (%s)\n' "$(batten --version 2>/dev/null || echo 'version unreadable')"
